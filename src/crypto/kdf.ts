import { scryptSync, pbkdf2Sync, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, mkdirSync, openSync, closeSync, writeSync, lstatSync, constants } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { homedir } from 'node:os';

export function deriveKeyScrypt(secret: string, salt: Buffer | string = 'obold-bcn-studio-kdf-salt-v1'): Buffer {
  const saltBuf = Buffer.isBuffer(salt) ? salt : Buffer.from(salt, 'utf-8');
  return scryptSync(secret, saltBuf, 32, { N: 16384, r: 8, p: 1 });
}

export function deriveKeyPbkdf2(secret: string, salt: Buffer | string = 'obold-bcn-studio-kdf-salt-v1'): Buffer {
  const saltBuf = Buffer.isBuffer(salt) ? salt : Buffer.from(salt, 'utf-8');
  return pbkdf2Sync(secret, saltBuf, 210000, 32, 'sha512');
}

export function validatePassphrasePolicy(passphrase: string): { valid: boolean; warning?: string } {
  if (passphrase.length < 12) {
    return {
      valid: false,
      warning: 'Weak passphrase detected: passphrases should be at least 12 characters long.',
    };
  }
  return { valid: true };
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
    try {
      const stat = lstatSync(targetKeyPath);
      if (stat.isSymbolicLink()) {
        throw new Error(`FATAL: Key file path "${targetKeyPath}" is a symbolic link. Insecure symlink key files are rejected.`);
      }
    } catch (err: any) {
      if (err.message.includes('FATAL:')) throw err;
    }

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
    const fd = openSync(targetKeyPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    writeSync(fd, `${generatedHex}\n`, 0, 'utf-8');
    closeSync(fd);
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

  const policy = validatePassphrasePolicy(trimmed);
  if (!policy.valid && policy.warning) {
    console.warn(`[SECURITY WARNING] ${policy.warning}`);
  }

  return deriveKeyScrypt(trimmed, salt);
}

export function zeroBuffer(buf: Buffer): void {
  buf.fill(0);
}
