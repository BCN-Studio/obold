import type { IPluginExecutor, PluginExecutionContext } from '../types.ts';
import type { ExecutionResult } from '../../config/types.ts';

export class DiscordPlugin implements IPluginExecutor {
  readonly id = 'core:discord';
  readonly name = 'Discord Webhook Notifier';
  readonly description = 'Dispatches rich embeds and role alerts to private Discord channels.';
  readonly version = '1.0.0';

  validateConfig(config: Record<string, any>): { valid: boolean; error?: string } {
    if (!config.webhook_url || typeof config.webhook_url !== 'string') {
      return { valid: false, error: 'Missing required field: "webhook_url".' };
    }

    if (!config.webhook_url.startsWith('https://discord.com/api/webhooks/') &&
        !config.webhook_url.startsWith('https://canary.discord.com/api/webhooks/') &&
        !config.webhook_url.startsWith('https://ptb.discord.com/api/webhooks/') &&
        !config.webhook_url.startsWith('http://127.0.0.1') &&
        !config.webhook_url.startsWith('http://localhost') &&
        !config.webhook_url.startsWith('https://127.0.0.1') &&
        !config.webhook_url.startsWith('https://localhost')) {
      return { valid: false, error: 'Invalid Discord webhook URL structure.' };
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
        output: { dryRun: true, message: 'Discord webhook payload validated.' },
      };
    }

    let webhookUrl = config.webhook_url;
    if (webhookUrl.startsWith('ENV:')) {
      webhookUrl = process.env[webhookUrl.substring(4)] || '';
    }

    let content = config.content || '';
    if (config.ping_role_id) {
      content = `<@&${config.ping_role_id}> ${content}`;
    }

    const embeds = config.embeds || [
      {
        title: config.title || `obold Alert: Switch [${context.switchName}] Triggered`,
        description: config.description || 'A dead man switch threshold has passed. Automated payload execution in progress.',
        color: config.color ? (typeof config.color === 'string' ? parseInt(config.color.replace('#', ''), 16) : config.color) : (context.isDuress ? 0xff0000 : 0xf59e0b),
        fields: [
          { name: 'Switch ID', value: context.switchId, inline: true },
          { name: 'Stage ID', value: context.stageId || 'Default', inline: true },
          { name: 'Timestamp (UTC)', value: new Date().toISOString(), inline: false },
        ],
        footer: {
          text: 'obold • Sovereign Dead Man\'s Switch (BCN Studio)',
          icon_url: 'https://bcnstudio.tech/favicon.ico',
        },
        timestamp: new Date().toISOString(),
      },
    ];

    const payload = {
      username: config.username || 'obold daemon',
      avatar_url: config.avatar_url || 'https://bcnstudio.tech/obold-avatar.png',
      content,
      embeds,
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
      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      clearTimeout(timer);
      const isSuccess = response.status >= 200 && response.status < 300;

      return {
        success: isSuccess,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        output: { statusCode: response.status },
        error: isSuccess ? undefined : `Discord API responded with HTTP ${response.status}`,
      };
    } catch (err: any) {
      clearTimeout(timer);
      return {
        success: false,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        error: err.name === 'AbortError' ? `Discord webhook timed out after ${timeoutMs}ms` : err.message,
      };
    }
  }
}
