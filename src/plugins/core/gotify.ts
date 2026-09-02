import type { IPluginExecutor, PluginExecutionContext } from '../types.ts';
import type { ExecutionResult } from '../../config/types.ts';

export class GotifyPlugin implements IPluginExecutor {
  readonly id = 'core:gotify';
  readonly name = 'Gotify Self-Hosted Server Notifier';
  readonly description = 'Dispatches real-time push messages and markdown alerts to self-hosted Gotify notification servers.';
  readonly version = '1.0.0';

  validateConfig(config: Record<string, any>): { valid: boolean; error?: string } {
    if (!config.server_url && !config.server) {
      return { valid: false, error: 'Missing required field: "server_url" or "server".' };
    }
    if (!config.app_token && !config.token) {
      return { valid: false, error: 'Missing required field: "app_token" or "token".' };
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

    const serverUrl = (config.server_url || config.server).replace(/\/+$/, '');
    const appToken = config.app_token || config.token;
    const endpoint = `${serverUrl}/message`;

    const title = config.title || `obold Alert: ${context.switchName}`;
    const text = config.message || config.text || config.body || `obold Dead Man's Switch Alert\n\nSwitch: ${context.switchName}\nStage: ${context.stageId || 'Default'}\nTimestamp: ${new Date().toISOString()}`;
    const priority = typeof config.priority === 'number' ? config.priority : (parseInt(config.priority, 10) || 5);

    if (context.dryRun) {
      return {
        success: true,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        output: { dryRun: true, serverUrl, title, priority },
      };
    }

    const extras: Record<string, any> = {};
    if (config.markdown !== false) {
      extras['client::display'] = { contentType: 'text/markdown' };
    }
    if (config.click_url || config.click) {
      extras['client::notification'] = { click: { url: config.click_url || config.click } };
    }
    if (config.extras && typeof config.extras === 'object') {
      Object.assign(extras, config.extras);
    }

    const payload: Record<string, any> = {
      title,
      message: text,
      priority,
      ...(Object.keys(extras).length > 0 ? { extras } : {}),
    };

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
        headers: {
          'X-Gotify-Key': appToken,
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
          error: `Gotify dispatch failed HTTP ${response.status} (${response.statusText}): ${errText.substring(0, 200)}`,
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
          id: data.id,
          serverUrl,
          title,
          priority,
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
        error: isTimeout ? `Gotify request timed out after ${timeoutMs}ms` : `Gotify dispatch failed: ${err.message}`,
      };
    }
  }
}
