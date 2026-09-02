import type { IPluginExecutor, PluginExecutionContext } from '../types.ts';
import type { ExecutionResult } from '../../config/types.ts';

export class SignalPlugin implements IPluginExecutor {
  readonly id = 'core:signal';
  readonly name = 'Signal Encrypted Messenger';
  readonly description = 'Dispatches end-to-end encrypted alert messages to Signal phone numbers via signal-cli REST gateway.';
  readonly version = '1.0.0';

  validateConfig(config: Record<string, any>): { valid: boolean; error?: string } {
    if (!config.api_url && !config.url && !config.server_url) {
      return { valid: false, error: 'Missing required field: "api_url" or "server_url" (signal-cli REST gateway URL).' };
    }
    if (!config.number && !config.sender_number && !config.sender) {
      return { valid: false, error: 'Missing required field: "number" (registered sender phone number, e.g. "+1234567890").' };
    }
    if (!config.recipients && !config.to) {
      return { valid: false, error: 'Missing required field: "recipients" or "to" (array or string of recipient phone numbers).' };
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

    const apiUrl = (config.api_url || config.url || config.server_url).replace(/\/+$/, '');
    const senderNumber = config.number || config.sender_number || config.sender;
    const recipientsRaw = config.recipients || config.to;
    const recipients: string[] = Array.isArray(recipientsRaw) ? recipientsRaw : [String(recipientsRaw)];
    const endpoint = `${apiUrl}/v2/send`;

    const text = config.message || config.text || config.body || `obold Dead Man's Switch Alert\n\nSwitch: ${context.switchName}\nStage: ${context.stageId || 'Default'}\nDeadline: ${new Date(context.deadlineAt).toISOString()}`;

    if (context.dryRun) {
      return {
        success: true,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        output: {
          dryRun: true,
          apiUrl,
          sender: senderNumber,
          recipients,
          messageSnippet: text.substring(0, 100),
        },
      };
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'obold-daemon/1.2.0 (+https://bcnstudio.tech)',
    };

    if (config.api_token || config.token) {
      headers['Authorization'] = `Bearer ${config.api_token || config.token}`;
    }

    if (config.api_key) {
      headers['X-API-Key'] = String(config.api_key);
    }

    if (config.headers && typeof config.headers === 'object') {
      Object.assign(headers, config.headers);
    }

    const payload: Record<string, any> = {
      number: senderNumber,
      recipients,
      message: text,
    };

    if (config.base64_attachments && Array.isArray(config.base64_attachments)) {
      payload.base64_attachments = config.base64_attachments;
    }

    const timeoutMs = config.timeout_ms || 20000;
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
          error: `Signal dispatch failed HTTP ${response.status} (${response.statusText}): ${errText.substring(0, 200)}`,
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
          sender: senderNumber,
          recipients,
          response: data,
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
        error: isTimeout ? `Signal request timed out after ${timeoutMs}ms` : `Signal dispatch failed: ${err.message}`,
      };
    }
  }
}
