import { createHmac, createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { HeartbeatToken } from '../config/types.ts';
import { normalizeMasterKey } from './kdf.ts';

export function constantTimeStringEquals(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const hashA = createHash('sha256').update(Buffer.from(a, 'utf-8')).digest();
  const hashB = createHash('sha256').update(Buffer.from(b, 'utf-8')).digest();
  return timingSafeEqual(hashA, hashB);
}

export class OboldTokenManager {
  private secret: Buffer;

  constructor(masterKey?: string) {
    this.secret = normalizeMasterKey(masterKey);
  }

  public generateToken(switchId: string, ttlMs: number = 86400000, isDuress: boolean = false): {
    rawToken: string;
    tokenRecord: HeartbeatToken;
  } {
    const id = `tkn-${Date.now()}-${randomBytes(4).toString('hex')}`;
    const expiresAt = Date.now() + ttlMs;
    const entropy = randomBytes(16).toString('hex');

    const message = `${id}:${switchId}:${expiresAt}:${isDuress ? '1' : '0'}:${entropy}`;
    const signature = createHmac('sha256', this.secret).update(message).digest('hex');

    const rawToken = `${Buffer.from(message).toString('base64url')}.${signature}`;
    const tokenHash = this.hashToken(rawToken);

    const tokenRecord: HeartbeatToken = {
      id,
      switchId,
      tokenHash,
      expiresAt,
      isDuress,
      createdAt: Date.now(),
    };

    return { rawToken, tokenRecord };
  }

  public parseAndVerifyToken(rawToken: string): {
    valid: boolean;
    switchId?: string;
    expiresAt?: number;
    isDuress?: boolean;
    error?: string;
  } {
    try {
      const parts = rawToken.split('.');
      if (parts.length !== 2) {
        return { valid: false, error: 'Malformed token structure.' };
      }

      const [encodedMessage, signature] = parts;
      const message = Buffer.from(encodedMessage, 'base64url').toString('utf-8');

      const expectedSignature = createHmac('sha256', this.secret).update(message).digest('hex');
      if (!constantTimeStringEquals(signature, expectedSignature)) {
        return { valid: false, error: 'Invalid cryptographic signature. Token may be forged.' };
      }

      const [id, switchId, expiresAtStr, duressFlag] = message.split(':');
      const expiresAt = parseInt(expiresAtStr, 10);
      const isDuress = duressFlag === '1';

      if (Date.now() > expiresAt) {
        return { valid: false, switchId, expiresAt, error: 'Token has expired.' };
      }

      return {
        valid: true,
        switchId,
        expiresAt,
        isDuress,
      };
    } catch (err: any) {
      return { valid: false, error: `Token parsing failed: ${err.message}` };
    }
  }

  public hashToken(rawToken: string): string {
    return createHash('sha256').update(rawToken).digest('hex');
  }
}
