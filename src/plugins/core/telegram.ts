import type { IPluginExecutor, PluginExecutionContext } from '../types.ts';
import type { ExecutionResult } from '../../config/types.ts';

export class TelegramPlugin implements IPluginExecutor {
  readonly id = 'core:telegram';
  readonly name = 'Telegram Bot Notifier';
  readonly description = 'Dispatches messages and interactive check-in buttons to Telegram chats or channels.';
  readonly version = '1.0.0';

  validateConfig(config: Record<string, any>): { valid: boolean; error?: string } {
    if (!config.bot_token || typeof config.bot_token !== 'string') {
      return { valid: false, error: 'Missing required field: "bot_token".' };
    }
    if (!config.chat_id) {
      return { valid: false, error: 'Missing required field: "chat_id".' };
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

    if (context.dryRun) {
      return {
        success: true,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        output: { dryRun: true, chat_id: config.chat_id },
      };
    }

    let botToken = config.bot_token;
    if (botToken.startsWith('ENV:')) {
      botToken = process.env[botToken.substring(4)] || '';
    }

    let chatId = config.chat_id;
    if (typeof chatId === 'string' && chatId.startsWith('ENV:')) {
      chatId = process.env[chatId.substring(4)] || '';
    }

    const text = config.text || `obold Dead Man's Switch Alert\n\nSwitch: *${context.switchName}*\nStage: ${context.stageId || 'Default'}\nTimestamp: ${new Date().toISOString()}`;

    const payload: Record<string, any> = {
      chat_id: chatId,
      text,
      parse_mode: config.parse_mode || 'Markdown',
      disable_web_page_preview: config.disable_preview !== false,
    };

    if (config.checkin_url) {
      payload.reply_markup = {
        inline_keyboard: [
          [
            {
              text: 'Confirm I am Alive (1-Tap Check-in)',
              url: config.checkin_url,
            },
          ],
        ],
      };
    }

    const base = config.api_base_url || 'https://api.telegram.org';
    const apiUrl = `${base.replace(/\/$/, '')}/bot${botToken}/sendMessage`;
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
      const response = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      clearTimeout(timer);
      const data: any = await response.json();

      if (data.ok) {
        return {
          success: true,
          actionId: context.actionId,
          plugin: this.id,
          durationMs: Date.now() - startTime,
          output: { messageId: data.result?.message_id },
        };
      } else {
        return {
          success: false,
          actionId: context.actionId,
          plugin: this.id,
          durationMs: Date.now() - startTime,
          error: `Telegram Error: ${data.description || 'Unknown error'}`,
        };
      }
    } catch (err: any) {
      clearTimeout(timer);
      return {
        success: false,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        error: err.name === 'AbortError' ? `Telegram request timed out after ${timeoutMs}ms` : err.message,
      };
    }
  }
}
