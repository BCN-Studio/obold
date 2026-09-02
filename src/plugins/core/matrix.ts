import type { IPluginExecutor, PluginExecutionContext } from '../types.ts';
import type { ExecutionResult } from '../../config/types.ts';

export class MatrixPlugin implements IPluginExecutor {
  readonly id = 'core:matrix';
  readonly name = 'Matrix Decentralized Chat Notifier';
  readonly description = 'Dispatches end-to-end alert notices and emergency messages to decentralized Matrix rooms via Matrix Client-Server REST API.';
  readonly version = '1.0.0';

  validateConfig(config: Record<string, any>): { valid: boolean; error?: string } {
    if (!config.homeserver && !config.homeserver_url) {
      return { valid: false, error: 'Missing required field: "homeserver" or "homeserver_url".' };
    }
    if (!config.room_id) {
      return { valid: false, error: 'Missing required field: "room_id" (e.g. "!abc:matrix.org").' };
    }
    if (!config.access_token) {
      return { valid: false, error: 'Missing required field: "access_token".' };
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

    const homeserver = (config.homeserver_url || config.homeserver).replace(/\/+$/, '');
    const roomId = config.room_id.trim();
    const accessToken = config.access_token;
    const txnId = context.idempotencyKey || `obold-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const endpoint = `${homeserver}/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/send/m.room.message/${encodeURIComponent(txnId)}`;

    const text = config.message || config.text || config.body || `obold Dead Man's Switch Alert\n\nSwitch: ${context.switchName}\nStage: ${context.stageId || 'Default'}\nTimestamp: ${new Date().toISOString()}`;

    if (context.dryRun) {
      return {
        success: true,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        output: { dryRun: true, homeserver, roomId, msgtype: config.msgtype || 'm.notice' },
      };
    }

    const payload: Record<string, any> = {
      msgtype: config.msgtype || 'm.notice',
      body: text,
    };

    if (config.formatted_body || config.html) {
      payload.format = 'org.matrix.custom.html';
      payload.formatted_body = config.formatted_body || config.html;
    }

    const timeoutMs = config.timeout_ms || 15000;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    if (context.signal) {
      if (context.signal.aborted) {
        controller.abort();
      } else {
        context.signal.addEventListener('abort', () => controller.abort(), { once: true });
      }
    }

    try {
      const response = await fetch(endpoint, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'User-Agent': 'obold-daemon/1.0.0-beta (+https://bcnstudio.tech)',
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (!response.ok) {
        const errText = await response.text().catch(() => '');
        return {
          success: false,
          actionId: context.actionId,
          plugin: this.id,
          durationMs: Date.now() - startTime,
          error: `Matrix send failed HTTP ${response.status} (${response.statusText}): ${errText.substring(0, 200)}`,
        };
      }

      let data: any = {};
      try {
        data = await response.json();
      } catch {
        data = { status: response.status };
      }

      return {
        success: true,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        output: {
          eventId: data.event_id,
          roomId,
          homeserver,
        },
      };
    } catch (err: any) {
      clearTimeout(timer);
      const isTimeout = err.name === 'AbortError';
      return {
        success: false,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        error: isTimeout ? `Matrix request timed out after ${timeoutMs}ms` : `Matrix dispatch failed: ${err.message}`,
      };
    }
  }
}
