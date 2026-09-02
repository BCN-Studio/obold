import { createHmac } from 'node:crypto';
import type { IPluginExecutor, PluginExecutionContext, PluginRiskTier } from '../types.ts';
import type { ExecutionResult } from '../../config/types.ts';
import { fetchWithSsrfGuard } from '../network-guard.ts';

export class WebhookPlugin implements IPluginExecutor {
  readonly id = 'core:webhook';
  readonly name = 'HTTP Webhook Dispatcher';
  readonly description = 'Dispatches signed HTTP requests to external APIs, Zapier, n8n, or internal endpoints.';
  readonly version = '1.0.0';
  readonly riskTier: PluginRiskTier = 'SENSITIVE_CORE';

  validateConfig(config: Record<string, any>): { valid: boolean; error?: string } {
    if (!config.target_url || typeof config.target_url !== 'string') {
      return { valid: false, error: 'Missing required field: "target_url" (string).' };
    }

    try {
      new URL(config.target_url);
    } catch {
      return { valid: false, error: `Invalid URL format: "${config.target_url}".` };
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
        output: { dryRun: true, target_url: config.target_url, method: config.http_method || 'POST' },
      };
    }

    const targetUrl = config.target_url;
    const method = (config.http_method || 'POST').toUpperCase();
    const headers: Record<string, string> = {
      'User-Agent': 'obold-daemon/1.0.0 (BCN Studio; +https://bcnstudio.tech)',
      'Content-Type': 'application/json',
      ...(context.idempotencyKey ? { 'X-Idempotency-Key': context.idempotencyKey } : {}),
      ...(config.headers || {}),
    };

    for (const [key, value] of Object.entries(headers)) {
      if (typeof value === 'string' && value.startsWith('ENV:')) {
        const envVar = value.substring(4);
        headers[key] = process.env[envVar] || '';
      }
    }

    const bodyObj = config.json_body || {
      event: 'obold.switch.triggered',
      switchId: context.switchId,
      switchName: context.switchName,
      stageId: context.stageId,
      actionId: context.actionId,
      triggeredAt: new Date().toISOString(),
      isDuress: context.isDuress || false,
    };
    const bodyStr = JSON.stringify(bodyObj);

    if (config.signing_secret) {
      const secret = config.signing_secret.startsWith('ENV:')
        ? process.env[config.signing_secret.substring(4)] || ''
        : config.signing_secret;
      const signature = createHmac('sha256', secret).update(bodyStr).digest('hex');
      headers['X-Obold-Signature'] = `sha256=${signature}`;
      headers['X-Obold-Timestamp'] = Date.now().toString();
    }

    const timeoutMs = config.timeout_ms || 30000;
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
      const allowPrivate = config.allow_private_network === true || config.allow_local === true;
      const response = await fetchWithSsrfGuard(
        targetUrl,
        {
          method,
          headers,
          body: method !== 'GET' && method !== 'HEAD' ? bodyStr : undefined,
          signal: controller.signal,
        },
        allowPrivate
      );

      clearTimeout(timer);
      const responseText = await response.text();
      const isSuccess = response.status >= 200 && response.status < 300;

      return {
        success: isSuccess,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        output: {
          statusCode: response.status,
          statusText: response.statusText,
          responseBody: responseText.substring(0, 1000),
        },
        error: isSuccess ? undefined : `HTTP Error ${response.status}: ${response.statusText}`,
      };
    } catch (err: any) {
      clearTimeout(timer);
      return {
        success: false,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        error: err.name === 'AbortError' ? `Webhook request timed out after ${timeoutMs}ms` : err.message,
      };
    }
  }
}
