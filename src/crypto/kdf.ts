import { scryptSync, pbkdf2Sync, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { homedir } from 'node:os';

export function deriveKeyScrypt(secret: string, salt: Buffer | string = 'obold-default-salt'): Buffer {
  const saltBuf = Buffer.isBuffer(salt) ? salt : Buffer.from(salt, 'utf-8');
  return scryptSync(secret, saltBuf, 32, { N: 16384, r: 8, p: 1 });
}

export function deriveKeyPbkdf2(secret: string, salt: Buffer | string = 'obold-default-salt'): Buffer {
  const saltBuf = Buffer.isBuffer(salt) ? salt : Buffer.from(salt, 'utf-8');
  return pbkdf2Sync(secret, saltBuf, 100000, 32, 'sha512');
}

export function getStableDefaultKeyPath(): string {
  if (process.env.OBOLD_MASTER_KEY_FILE && process.env.OBOLD_MASTER_KEY_FILE.trim().length > 0) {
    return resolve(process.env.OBOLD_MASTER_KEY_FILE.trim());
  }
  if (process.env.OBOLD_KEY_FILE && process.env.OBOLD_KEY_FILE.trim().length > 0) {
    return resolve(process.env.OBOLD_KEY_FILE.trim());
  }

  const home = homedir();
  if (process.platform === 'win32') {
    const localAppData = process.env.LOCALAPPDATA || process.env.APPDATA || (home ? resolve(home, 'AppData', 'Local') : 'C:\\');
    return resolve(localAppData, 'obold', 'master.key');
  }

  const xdgData = process.env.XDG_DATA_HOME || (home ? resolve(home, '.local', 'share') : '/var/lib');
  return resolve(xdgData, 'obold', 'master.key');
}

export function resolveMasterKey(customKey?: string, keyFilePath?: string): Buffer {
  if (customKey && customKey.trim().length > 0) {
    return normalizeMasterKey(customKey.trim());
  }

  const envKey = process.env.OBOLD_MASTER_KEY || process.env.OBOLD_PASSPHRASE;
  if (envKey && envKey.trim().length > 0) {
    return normalizeMasterKey(envKey.trim());
  }

  const targetKeyPath = keyFilePath || getStableDefaultKeyPath();
  if (existsSync(targetKeyPath)) {
    const fileContent = readFileSync(targetKeyPath, 'utf-8').trim();
    if (fileContent.length > 0) {
      return normalizeMasterKey(fileContent);
    }
  }

  const targetDir = dirname(targetKeyPath);
  if (!existsSync(targetDir)) {
    try {
      mkdirSync(targetDir, { recursive: true, mode: 0o700 });
    } catch (err: any) {
      throw new Error(`FATAL: Failed to create key directory at "${targetDir}": ${err?.message || err}`);
    }
  }

  const generatedHex = randomBytes(32).toString('hex');
  try {
    writeFileSync(targetKeyPath, `${generatedHex}\n`, { encoding: 'utf-8', mode: 0o600 });
  } catch (err: any) {
    throw new Error(`FATAL: Refusing to start because master encryption key could not be persisted to "${targetKeyPath}": ${err?.message || err}`);
  }

  return Buffer.from(generatedHex, 'hex');
}

export function normalizeMasterKey(masterKeyInput?: string, salt: Buffer | string = 'obold-bcn-studio-kdf-salt-v1'): Buffer {
  if (!masterKeyInput || masterKeyInput.trim().length === 0) {
    return resolveMasterKey();
  }

  const trimmed = masterKeyInput.trim();

  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    return Buffer.from(trimmed, 'hex');
  }

  return deriveKeyScrypt(trimmed, salt);
}

export function zeroBuffer(buf: Buffer): void {
  buf.fill(0);
}
