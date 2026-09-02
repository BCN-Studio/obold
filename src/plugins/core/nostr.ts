import { createHash } from 'node:crypto';
import type { IPluginExecutor, PluginExecutionContext } from '../types.ts';
import type { ExecutionResult } from '../../config/types.ts';

export class NostrPlugin implements IPluginExecutor {
  readonly id = 'core:nostr';
  readonly name = 'Nostr Decentralized Broadcast';
  readonly description = 'Publishes immutable broadcasts to decentralized Nostr relays.';
  readonly version = '1.0.0';

  validateConfig(config: Record<string, any>): { valid: boolean; error?: string } {
    if (!config.relays || (Array.isArray(config.relays) && config.relays.length === 0)) {
      return { valid: false, error: 'Missing required field: "relays" (array of WebSocket relay URLs).' };
    }
    if (!config.content) {
      return { valid: false, error: 'Missing required field: "content" (note body).' };
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

    
    const createdAt = Math.floor(Date.now() / 1000);
    const pubkey = config.pubkey || '0000000000000000000000000000000000000000000000000000000000000000';
    const kind = config.kind || 1;
    const tags = config.tags || [['t', 'obold'], ['t', 'deadmanswitch']];

    const serialized = JSON.stringify([0, pubkey, createdAt, kind, tags, content]);
    const eventId = createHash('sha256').update(serialized).digest('hex');

    const event = {
      id: eventId,
      pubkey,
      created_at: createdAt,
      kind,
      tags,
      content,
      sig: config.sig || '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
    };

    const message = JSON.stringify(['EVENT', event]);
    let successCount = 0;
    const errors: string[] = [];
    const activeSockets: WebSocket[] = [];

    const abortHandler = () => {
      for (const ws of activeSockets) {
        try { ws.close(); } catch {}
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

    try {
      await Promise.all(
        relays.map(
          (relayUrl: string) =>
            new Promise<void>((resolve) => {
              try {
                const ws = new WebSocket(relayUrl);
                activeSockets.push(ws);

                const timer = setTimeout(() => {
                  try { ws.close(); } catch {}
                  errors.push(`Timeout connecting to relay ${relayUrl}`);
                  resolve();
                }, 8000);

                ws.onopen = () => {
                  try { ws.send(message); } catch {}
                  successCount++;
                  clearTimeout(timer);
                  setTimeout(() => {
                    try { ws.close(); } catch {}
                    resolve();
                  }, 1000);
                };

                ws.onerror = (err: any) => {
                  clearTimeout(timer);
                  errors.push(`Relay ${relayUrl} error: ${err.message || 'connection failed'}`);
                  resolve();
                };
              } catch (err: any) {
                errors.push(`Relay ${relayUrl} exception: ${err.message}`);
                resolve();
              }
            })
        )
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
      output: { eventId, publishedTo: successCount, totalRelays: relays.length },
      error: isSuccess ? undefined : `Failed to publish to any relay: ${errors.join(', ')}`,
    };
  }
}
