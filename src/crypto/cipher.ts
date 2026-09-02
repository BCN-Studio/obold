import { createCipheriv, createDecipheriv, randomBytes, getCiphers } from 'node:crypto';
import { normalizeMasterKey, zeroBuffer } from './kdf.ts';

export interface EncryptedPayload {
  algorithm: 'aes-256-gcm' | 'chacha20-poly1305';
  iv: string;
  tag: string;
  data: string;
}

export class OboldCipher {
  private key: Buffer;
  private defaultAlgorithm: 'aes-256-gcm' | 'chacha20-poly1305';

  constructor(masterKey?: string, algorithm: 'aes-256-gcm' | 'chacha20-poly1305' = 'aes-256-gcm', salt?: Buffer | string) {
    this.key = normalizeMasterKey(masterKey, salt);
    this.defaultAlgorithm = algorithm;
  }

  public encrypt(plaintext: string | object, algorithm?: 'aes-256-gcm' | 'chacha20-poly1305', aad?: Buffer | string): EncryptedPayload {
    const requestedAlgo = algorithm || this.defaultAlgorithm;
    const text = typeof plaintext === 'object' ? JSON.stringify(plaintext) : plaintext;
    const textBuffer = Buffer.from(text, 'utf-8');

    const supportedCiphers = getCiphers();
    const effectiveAlgo = (requestedAlgo === 'chacha20-poly1305' && supportedCiphers.includes('chacha20-poly1305'))
      ? 'chacha20-poly1305'
      : 'aes-256-gcm';

    const iv = randomBytes(12);
    const cipher = createCipheriv(effectiveAlgo, this.key, iv, {
      authTagLength: 16,
    } as any);

    if (aad) {
      const aadBuf = Buffer.isBuffer(aad) ? aad : Buffer.from(aad, 'utf-8');
      (cipher as any).setAAD(aadBuf, { plaintextLength: textBuffer.length });
    }

    const encrypted = Buffer.concat([cipher.update(textBuffer), cipher.final()]);
    const tag = (cipher as any).getAuthTag();

    return {
      algorithm: effectiveAlgo,
      iv: iv.toString('hex'),
      tag: tag.toString('hex'),
      data: encrypted.toString('hex'),
    };
  }

  public decrypt(payload: EncryptedPayload, aad?: Buffer | string): string {
    const iv = Buffer.from(payload.iv, 'hex');
    const tag = Buffer.from(payload.tag, 'hex');
    const ciphertext = Buffer.from(payload.data, 'hex');

    const algo = payload.algorithm === 'chacha20-poly1305' ? 'chacha20-poly1305' : 'aes-256-gcm';

    const decipher = createDecipheriv(algo, this.key, iv, {
      authTagLength: 16,
    } as any);

    if (aad) {
      const aadBuf = Buffer.isBuffer(aad) ? aad : Buffer.from(aad, 'utf-8');
      (decipher as any).setAAD(aadBuf, { plaintextLength: ciphertext.length });
    }

    (decipher as any).setAuthTag(tag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf-8');
  }

  public encryptToString(plaintext: string | object, aad?: Buffer | string): string {
    const payload = this.encrypt(plaintext, undefined, aad);
    return `enc:${Buffer.from(JSON.stringify(payload)).toString('base64')}`;
  }

  public decryptFromString(encryptedString: string, aad?: Buffer | string): string {
    if (!encryptedString.startsWith('enc:')) {
      return encryptedString;
    }
    const jsonStr = Buffer.from(encryptedString.substring(4), 'base64').toString('utf-8');
    const payload: EncryptedPayload = JSON.parse(jsonStr);
    return this.decrypt(payload, aad);
  }

  public destroy(): void {
    zeroBuffer(this.key);
  }
}
