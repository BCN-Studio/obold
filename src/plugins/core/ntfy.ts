import type { IPluginExecutor, PluginExecutionContext } from '../types.ts';
import type { ExecutionResult } from '../../config/types.ts';

export class NtfyPlugin implements IPluginExecutor {
  readonly id = 'core:ntfy';
  readonly name = 'ntfy PubSub Push Notifier';
  readonly description = 'Dispatches instant push alerts, emergency notifications, and action buttons via ntfy.sh or self-hosted ntfy servers.';
  readonly version = '1.0.0';

  validateConfig(config: Record<string, any>): { valid: boolean; error?: string } {
    if (!config.topic || typeof config.topic !== 'string') {
      return { valid: false, error: 'Missing required field: "topic" (ntfy channel/topic name).' };
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

    const serverUrl = (config.server_url || config.server || 'https://ntfy.sh').replace(/\/+$/, '');
    const topic = config.topic.trim();
    const endpoint = `${serverUrl}/${encodeURIComponent(topic)}`;

    const title = config.title || `obold Alert: ${context.switchName}`;
    const message = config.message || config.text || config.body || `obold Dead Man's Switch Alert\nSwitch: ${context.switchName}\nStage: ${context.stageId || 'Default'}\nDeadline: ${new Date(context.deadlineAt).toISOString()}`;

    if (context.dryRun) {
      return {
        success: true,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        output: { dryRun: true, serverUrl, topic, title },
      };
    }

    const headers: Record<string, string> = {
      'User-Agent': 'obold-daemon/1.0.0-beta (+https://bcnstudio.tech)',
      'Title': title,
      ...(context.idempotencyKey ? { 'X-Idempotency-Key': context.idempotencyKey } : {}),
    };

    if (config.priority) {
      headers['Priority'] = String(config.priority);
    }

    if (config.tags) {
      headers['Tags'] = Array.isArray(config.tags) ? config.tags.join(',') : String(config.tags);
    }

    if (config.click || config.click_url) {
      headers['Click'] = String(config.click || config.click_url);
    }

    if (config.actions) {
      headers['Actions'] = Array.isArray(config.actions) ? JSON.stringify(config.actions) : String(config.actions);
    }

    if (config.attach || config.attachment) {
      headers['Attach'] = String(config.attach || config.attachment);
    }

    if (config.email) {
      headers['X-Email'] = String(config.email);
    }

    if (config.auth_token || config.token) {
      headers['Authorization'] = `Bearer ${config.auth_token || config.token}`;
    } else if (config.username && config.password) {
      const creds = Buffer.from(`${config.username}:${config.password}`).toString('base64');
      headers['Authorization'] = `Basic ${creds}`;
    }

    if (config.headers && typeof config.headers === 'object') {
      Object.assign(headers, config.headers);
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
        method: 'POST',
        headers,
        body: message,
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (!response.ok) {
        const errorText = await response.text().catch(() => '');
        return {
          success: false,
          actionId: context.actionId,
          plugin: this.id,
          durationMs: Date.now() - startTime,
          error: `ntfy publish failed HTTP ${response.status} (${response.statusText}): ${errorText.substring(0, 200)}`,
        };
      }

      let responseData: any = {};
      try {
        responseData = await response.json();
      } catch {
        responseData = { status: response.status, statusText: response.statusText };
      }

      return {
        success: true,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        output: {
          serverUrl,
          topic,
          statusCode: response.status,
          response: responseData,
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
        error: isTimeout ? `ntfy request timed out after ${timeoutMs}ms` : `ntfy delivery failed: ${err.message}`,
      };
    }
  }
}
