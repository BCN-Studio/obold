import { createHash } from 'node:crypto';
import { schnorr } from '@noble/curves/secp256k1.js';
import type { IPluginExecutor, PluginExecutionContext } from '../types.ts';
import type { ExecutionResult } from '../../config/types.ts';
import { createWebSocketWithSsrfGuard } from '../network-guard.ts';

export class NostrPlugin implements IPluginExecutor {
  readonly id = 'core:nostr';
  readonly name = 'Nostr Decentralized Broadcast';
  readonly description = 'Publishes cryptographically signed broadcasts to decentralized Nostr relays.';
  readonly version = '1.0.0';

  validateConfig(config: Record<string, any>): { valid: boolean; error?: string } {
    if (!config.relays || (Array.isArray(config.relays) && config.relays.length === 0)) {
      return { valid: false, error: 'Missing required field: "relays" (array of WebSocket relay URLs).' };
    }
    if (!config.content) {
      return { valid: false, error: 'Missing required field: "content" (note body).' };
    }

    if (!config.private_key || typeof config.private_key !== 'string') {
      return {
        valid: false,
        error: 'Missing required field: "private_key" (64-character hex encoded secp256k1 private key or ENV:VAR_NAME).',
      };
    }

    if (config.private_key.startsWith('ENV:')) {
      const envKey = config.private_key.substring(4).trim();
      const val = process.env[envKey];
      if (!val || val.trim().length === 0) {
        return { valid: false, error: `Missing required environment variable "${envKey}" for Nostr private key.` };
      }
      if (!/^[0-9a-fA-F]{64}$/.test(val.trim())) {
        return { valid: false, error: `Invalid private key in "${envKey}": must be 64 hexadecimal characters.` };
      }
    } else {
      if (!/^[0-9a-fA-F]{64}$/.test(config.private_key.trim())) {
        return { valid: false, error: 'Invalid "private_key": must be 64 hexadecimal characters.' };
      }
    }

    return { valid: true };
  }

  async execute(config: Record<string, any>, context: PluginExecutionContext): Promise<ExecutionResult> {
    const startTime = Date.now();
    const validation = this.validateConfig(config);
    if (!validation.valid) {
      return {
        success: false,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: 0,
        error: validation.error,
      };
    }

    const relays = Array.isArray(config.relays) ? config.relays : [config.relays];
    const content = config.content;

    if (context.dryRun) {
      return {
        success: true,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        output: { dryRun: true, relays, contentSnippet: content.substring(0, 100) },
      };
    }

    let rawKey = config.private_key.trim();
    if (rawKey.startsWith('ENV:')) {
      rawKey = (process.env[rawKey.substring(4).trim()] || '').trim();
    }

    let privKeyBytes: Uint8Array;
    let pubkeyHex: string;
    try {
      privKeyBytes = Uint8Array.from(Buffer.from(rawKey, 'hex'));
      if (privKeyBytes.length !== 32) {
        throw new Error('Private key must be exactly 32 bytes (64 hex characters).');
      }
      const pubkeyBytes = schnorr.getPublicKey(privKeyBytes);
      pubkeyHex = Buffer.from(pubkeyBytes).toString('hex');
    } catch (err: any) {
      return {
        success: false,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        error: `Nostr Key Derivation Error: ${err.message}`,
      };
    }

    const createdAt = Math.floor(Date.now() / 1000);
    const kind = config.kind || 1;
    const tags = config.tags || [['t', 'obold'], ['t', 'deadmanswitch']];

    const serialized = JSON.stringify([0, pubkeyHex, createdAt, kind, tags, content]);
    const eventId = createHash('sha256').update(serialized).digest('hex');
    const idBytes = Uint8Array.from(Buffer.from(eventId, 'hex'));

    let sigHex: string;
    try {
      const sigBytes = schnorr.sign(idBytes, privKeyBytes);
      sigHex = Buffer.from(sigBytes).toString('hex');
    } catch (err: any) {
      return {
        success: false,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        error: `Nostr BIP-340 Signing Error: ${err.message}`,
      };
    }

    const event = {
      id: eventId,
      pubkey: pubkeyHex,
      created_at: createdAt,
      kind,
      tags,
      content,
      sig: sigHex,
    };

    const message = JSON.stringify(['EVENT', event]);
    let successCount = 0;
    const errors: string[] = [];
    const activeSockets: WebSocket[] = [];

    const abortHandler = () => {
      for (const ws of activeSockets) {
        try {
          ws.close();
        } catch {}
      }
    };

    if (context.signal) {
      if (context.signal.aborted) {
        return {
          success: false,
          actionId: context.actionId,
          plugin: this.id,
          durationMs: Date.now() - startTime,
          error: 'Nostr publish cancelled by abort signal before connect',
        };
      }
      context.signal.addEventListener('abort', abortHandler, { once: true });
    }

    const allowPrivate = config.allow_private_network === true || config.allow_local === true;

    try {
      await Promise.all(
        relays.map(async (relayUrl: string) => {
          return new Promise<void>((resolve) => {
            let isSettled = false;
            let ws: WebSocket | undefined;

            const timer = setTimeout(() => {
              finish(`Timeout waiting for OK from relay ${relayUrl}`);
            }, config.timeout_ms || 8000);

            const finish = (errMessage?: string) => {
              if (isSettled) return;
              isSettled = true;
              clearTimeout(timer);
              if (errMessage) errors.push(errMessage);
              if (ws) {
                try {
                  ws.close();
                } catch {}
              }
              resolve();
            };

            createWebSocketWithSsrfGuard(relayUrl, allowPrivate)
              .then(({ ws: guardedWs }) => {
                ws = guardedWs;
                activeSockets.push(ws);

                ws.onopen = () => {
                  try {
                    ws?.send(message);
                  } catch (err: any) {
                    finish(`Failed to send event to ${relayUrl}: ${err.message}`);
                  }
                };

                ws.onmessage = (eventMsg: MessageEvent) => {
                  try {
                    const data = JSON.parse(eventMsg.data);
                    if (Array.isArray(data) && data[0] === 'OK' && data[1] === eventId) {
                      const isAccepted = data[2] === true;
                      if (isAccepted) {
                        successCount++;
                        finish();
                      } else {
                        const reason = data[3] || 'Relay rejected event';
                        finish(`Relay ${relayUrl} rejected event: ${reason}`);
                      }
                    } else if (Array.isArray(data) && data[0] === 'NOTICE') {
                      errors.push(`Relay ${relayUrl} notice: ${data[1]}`);
                    }
                  } catch {}
                };

                ws.onerror = (err: any) => {
                  finish(`Relay ${relayUrl} connection error: ${err?.message || 'unknown error'}`);
                };

                ws.onclose = () => {
                  if (!isSettled) {
                    finish(`Relay ${relayUrl} closed connection before acknowledging event`);
                  }
                };
              })
              .catch((err: any) => {
                finish(`Relay ${relayUrl} SSRF or connection error: ${err?.message || err}`);
              });
          });
        })
      );
    } finally {
      if (context.signal) {
        context.signal.removeEventListener('abort', abortHandler);
      }
    }

    const isSuccess = successCount > 0;

    return {
      success: isSuccess,
      actionId: context.actionId,
      plugin: this.id,
      durationMs: Date.now() - startTime,
      output: { eventId, pubkey: pubkeyHex, publishedTo: successCount, totalRelays: relays.length },
      error: isSuccess ? undefined : `Failed to publish to any relay: ${errors.join('; ')}`,
    };
  }
}
