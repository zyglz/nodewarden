import { useState } from 'preact/hooks';
import { argon2idAsync } from '@noble/hashes/argon2.js';
import { strFromU8, unzipSync } from 'fflate';
import { FileUp } from 'lucide-preact';
import ConfirmDialog from '@/components/ConfirmDialog';
import type { CiphersImportPayload } from '@/lib/api';
import {
  getFileAcceptBySource,
  IMPORT_SOURCES,
  type BitwardenJsonInput,
  type ImportSourceId,
  normalizeBitwardenEncryptedAccountImport,
  normalizeBitwardenImport,
  parseImportPayloadBySource,
} from '@/lib/import-formats';
import { base64ToBytes, decryptStr, hkdfExpand, pbkdf2 } from '@/lib/crypto';
import { t } from '@/lib/i18n';
import type { Folder } from '@/lib/types';

interface ImportPageProps {
  onImport: (
    payload: CiphersImportPayload,
    options: { folderMode: 'original' | 'none' | 'target'; targetFolderId: string | null }
  ) => Promise<void>;
  onImportEncryptedRaw: (
    payload: CiphersImportPayload,
    options: { folderMode: 'original' | 'none' | 'target'; targetFolderId: string | null }
  ) => Promise<void>;
  accountKeys?: { encB64: string; macB64: string } | null;
  onNotify: (type: 'success' | 'error', text: string) => void;
  folders: Folder[];
}

interface BitwardenPasswordProtectedInput extends BitwardenJsonInput {
  encrypted: true;
  passwordProtected: true;
  salt?: string;
  kdfIterations?: number;
  kdfMemory?: number;
  kdfParallelism?: number;
  kdfType?: number;
  data?: string;
}

const COMMON_IMPORT_SOURCE_IDS: ImportSourceId[] = [
  'bitwarden_json',
  'bitwarden_csv',
  'onepassword_1pux',
  'onepassword_1pif',
  'onepassword_mac_csv',
  'onepassword_win_csv',
  'protonpass_json',
  'chrome',
  'edge',
  'brave',
  'opera',
  'vivaldi',
  'firefox_csv',
  'safari_csv',
  'lastpass',
  'dashlane_csv',
  'dashlane_json',
  'keepass_xml',
  'keepassx_csv',
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

function isPasswordProtectedExport(value: unknown): value is BitwardenPasswordProtectedInput {
  return isRecord(value) && value.encrypted === true && value.passwordProtected === true;
}

async function derivePasswordProtectedFileKey(
  parsed: BitwardenPasswordProtectedInput,
  password: string
): Promise<{ enc: Uint8Array; mac: Uint8Array }> {
  const salt = String(parsed.salt || '').trim();
  const iterations = Number(parsed.kdfIterations || 0);
  const kdfType = Number(parsed.kdfType);
  if (!salt || !Number.isFinite(iterations) || iterations <= 0) {
    throw new Error('Invalid password-protected export file.');
  }

  let keyMaterial: Uint8Array;
  if (kdfType === 0) {
    keyMaterial = await pbkdf2(password, salt, iterations, 32);
  } else if (kdfType === 1) {
    const memoryMiB = Number(parsed.kdfMemory || 0);
    const parallelism = Number(parsed.kdfParallelism || 0);
    if (!Number.isFinite(memoryMiB) || memoryMiB <= 0 || !Number.isFinite(parallelism) || parallelism <= 0) {
      throw new Error('Invalid Argon2id parameters in export file.');
    }
    const memoryKiB = Math.floor(memoryMiB * 1024);
    const maxmem = memoryKiB * 1024 + 1024 * 1024;
    keyMaterial = await argon2idAsync(new TextEncoder().encode(password), new TextEncoder().encode(salt), {
      t: Math.floor(iterations),
      m: memoryKiB,
      p: Math.floor(parallelism),
      dkLen: 32,
      maxmem,
      asyncTick: 10,
    });
  } else {
    throw new Error(`Unsupported kdfType: ${kdfType}`);
  }

  const enc = await hkdfExpand(keyMaterial, 'enc', 32);
  const mac = await hkdfExpand(keyMaterial, 'mac', 32);
  return { enc, mac };
}

async function decryptPasswordProtectedExport(parsed: BitwardenPasswordProtectedInput, password: string): Promise<unknown> {
  if (!parsed.encKeyValidation_DO_NOT_EDIT || !parsed.data) {
    throw new Error('Invalid password-protected export file.');
  }
  const pass = String(password || '').trim();
  if (!pass) {
    throw new Error('Please enter file password.');
  }

  const key = await derivePasswordProtectedFileKey(parsed, pass);
  try {
    await decryptStr(parsed.encKeyValidation_DO_NOT_EDIT, key.enc, key.mac);
  } catch {
    throw new Error('Invalid file password.');
  }

  const plainJson = await decryptStr(parsed.data, key.enc, key.mac);
  try {
    return JSON.parse(plainJson);
  } catch {
    throw new Error('Failed to decrypt import file.');
  }
}

function isZipPayload(bytes: Uint8Array): boolean {
  return bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04;
}

function readZipText(bytes: Uint8Array, source: ImportSourceId): string {
  const unzipped = unzipSync(bytes);
  const fileNames = Object.keys(unzipped);
  if (!fileNames.length) throw new Error('Empty zip archive.');

  const preferred = source === 'onepassword_1pux' ? ['export.data', 'export.json'] : ['protonpass.json', 'export.json'];
  for (const p of preferred) {
    const hit = fileNames.find((n) => n.toLowerCase().endsWith(p.toLowerCase()));
    if (hit) return strFromU8(unzipped[hit]);
  }

  const firstJson = fileNames.find((n) => n.toLowerCase().endsWith('.json') || n.toLowerCase().endsWith('.data'));
  if (firstJson) return strFromU8(unzipped[firstJson]);
  throw new Error('No importable JSON data found in zip archive.');
}

async function readImportText(file: File, source: ImportSourceId): Promise<string> {
  if (source !== 'onepassword_1pux' && source !== 'protonpass_json') {
    return file.text();
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (isZipPayload(bytes)) return readZipText(bytes, source);
  return new TextDecoder().decode(bytes);
}

export default function ImportPage({ onImport, onImportEncryptedRaw, accountKeys, onNotify, folders }: ImportPageProps) {
  const [source, setSource] = useState<ImportSourceId>('bitwarden_json');
  const [file, setFile] = useState<File | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isPasswordSubmitting, setIsPasswordSubmitting] = useState(false);
  const [passwordDialogOpen, setPasswordDialogOpen] = useState(false);
  const [importPassword, setImportPassword] = useState('');
  const [pendingPasswordImport, setPendingPasswordImport] = useState<BitwardenPasswordProtectedInput | null>(null);
  const [folderMode, setFolderMode] = useState<'original' | 'none' | 'target'>('original');
  const [targetFolderId, setTargetFolderId] = useState('');
  const commonSourceSet = new Set<ImportSourceId>(COMMON_IMPORT_SOURCE_IDS);
  const commonSources = IMPORT_SOURCES.filter((item) => commonSourceSet.has(item.id as ImportSourceId));
  const otherSources = IMPORT_SOURCES.filter((item) => !commonSourceSet.has(item.id as ImportSourceId));

  async function runBitwardenJsonImport(parsed: unknown): Promise<void> {
    if (isRecord(parsed) && parsed.encrypted === true) {
      const accountEncrypted = parsed as BitwardenJsonInput;
      if (!accountKeys?.encB64 || !accountKeys?.macB64) {
        throw new Error('Vault key unavailable. Please unlock vault and try again.');
      }
      const validation = String(accountEncrypted.encKeyValidation_DO_NOT_EDIT || '').trim();
      if (!validation) throw new Error('Invalid encrypted export file.');
      const accountEncKey = base64ToBytes(accountKeys.encB64);
      const accountMacKey = base64ToBytes(accountKeys.macB64);
      try {
        await decryptStr(validation, accountEncKey, accountMacKey);
      } catch {
        throw new Error('This encrypted export belongs to another account.');
      }
      await onImportEncryptedRaw(normalizeBitwardenEncryptedAccountImport(accountEncrypted), {
        folderMode,
        targetFolderId: folderMode === 'target' ? targetFolderId || null : null,
      });
      return;
    }
    await onImport(normalizeBitwardenImport(parsed), {
      folderMode,
      targetFolderId: folderMode === 'target' ? targetFolderId || null : null,
    });
  }

  async function handleSubmit() {
    if (!file) {
      onNotify('error', t('txt_please_select_a_file'));
      return;
    }

    setIsSubmitting(true);
    try {
      const text = await readImportText(file, source);
      if (source === 'bitwarden_json') {
        let parsed: unknown;
        try {
          parsed = JSON.parse(text);
        } catch {
          throw new Error('Invalid JSON file');
        }
        if (isPasswordProtectedExport(parsed)) {
          setPendingPasswordImport(parsed);
          setImportPassword('');
          setPasswordDialogOpen(true);
          return;
        }
        await runBitwardenJsonImport(parsed);
      } else {
        await onImport(parseImportPayloadBySource(source, text), {
          folderMode,
          targetFolderId: folderMode === 'target' ? targetFolderId || null : null,
        });
      }
      setFile(null);
      onNotify('success', 'Import completed');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Import failed';
      onNotify('error', message);
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handlePasswordImportConfirm() {
    if (!pendingPasswordImport) return;
    setIsPasswordSubmitting(true);
    try {
      const parsed = await decryptPasswordProtectedExport(pendingPasswordImport, importPassword);
      await runBitwardenJsonImport(parsed);
      setFile(null);
      setImportPassword('');
      setPendingPasswordImport(null);
      setPasswordDialogOpen(false);
      onNotify('success', 'Import completed');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Import failed';
      onNotify('error', message);
    } finally {
      setIsPasswordSubmitting(false);
    }
  }

  return (
    <div className="stack">
      <section className="card">
        <h3>Import</h3>
        <p className="muted" style={{ textAlign: 'left', marginBottom: 12 }}>
          Import vault data into your current account.
        </p>
        <div className="field-grid">
          <label className="field field-span-2">
            <span>Format</span>
            <select className="input" value={source} onChange={(e) => setSource((e.currentTarget as HTMLSelectElement).value as ImportSourceId)}>
              {commonSources.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.label}
                </option>
              ))}
              {otherSources.length > 0 && (
                <option disabled value="__separator__">
                  --------------------
                </option>
              )}
              {otherSources.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>

          <label className="field field-span-2">
            <span>Source file</span>
            <input
              className="input"
              type="file"
              accept={getFileAcceptBySource(source)}
              onChange={(e) => {
                const next = (e.currentTarget as HTMLInputElement).files?.[0] || null;
                setFile(next);
              }}
            />
          </label>

          <label className="field field-span-2">
            <span>Folder handling</span>
            <select
              className="input"
              value={folderMode}
              onChange={(e) => setFolderMode((e.currentTarget as HTMLSelectElement).value as 'original' | 'none' | 'target')}
            >
              <option value="original">Original path from import file</option>
              <option value="none">No folder</option>
              <option value="target">One selected folder</option>
            </select>
          </label>

          {folderMode === 'target' && (
            <label className="field field-span-2">
              <span>Target folder</span>
              <select className="input" value={targetFolderId} onChange={(e) => setTargetFolderId((e.currentTarget as HTMLSelectElement).value)}>
                <option value="">-- Select folder --</option>
                {folders
                  .slice()
                  .sort((a, b) => String(a.decName || a.name || '').localeCompare(String(b.decName || b.name || '')))
                  .map((folder) => (
                    <option key={folder.id} value={folder.id}>
                      {folder.decName || folder.name || folder.id}
                    </option>
                  ))}
              </select>
            </label>
          )}
        </div>

        <div className="actions">
          <button
            type="button"
            className="btn btn-primary"
            disabled={isSubmitting || (folderMode === 'target' && !targetFolderId)}
            onClick={() => void handleSubmit()}
          >
            <FileUp size={15} /> {isSubmitting ? t('txt_loading') : 'Import'}
          </button>
        </div>
      </section>

      <ConfirmDialog
        open={passwordDialogOpen}
        title="Import encrypted file"
        message="This Bitwarden export is password-protected. Enter the export file password to continue."
        confirmText={isPasswordSubmitting ? t('txt_loading') : 'Import'}
        cancelText={t('txt_cancel')}
        showIcon={false}
        onConfirm={() => void handlePasswordImportConfirm()}
        onCancel={() => {
          if (isPasswordSubmitting) return;
          setPasswordDialogOpen(false);
          setImportPassword('');
          setPendingPasswordImport(null);
        }}
      >
        <label className="field">
          <span>File password</span>
          <input
            className="input"
            type="password"
            value={importPassword}
            onInput={(e) => setImportPassword((e.currentTarget as HTMLInputElement).value)}
          />
        </label>
      </ConfirmDialog>
    </div>
  );
}
