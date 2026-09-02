import type { IPluginExecutor, PluginExecutionContext } from '../types.ts';
import type { ExecutionResult } from '../../config/types.ts';
import { ShamirSecretSharing } from '../../crypto/shamir.ts';
import { createDefaultPluginRegistry, type PluginRegistry } from '../registry.ts';

export class ShamirDistributePlugin implements IPluginExecutor {
  readonly id = 'core:shamir_distribute';
  readonly name = 'Dynamic Shamir Secret Sharding Distributor';
  readonly description = 'Splits critical master secrets into k-of-n Shamir shares at trigger time and routes individual shares across disparate channels.';
  readonly version = '1.0.0';

  validateConfig(config: Record<string, any>): { valid: boolean; error?: string } {
    if (!config.secret && !config.payload) {
      return { valid: false, error: 'Missing required field: "secret" or "payload" to shard.' };
    }
    if (!Array.isArray(config.channels) || config.channels.length < 2) {
      return { valid: false, error: 'Field "channels" must be an array of at least 2 target destination channels.' };
    }

    const threshold = config.threshold || 2;
    if (threshold < 2) {
      return { valid: false, error: 'Threshold "threshold" must be at least 2.' };
    }
    if (threshold > config.channels.length) {
      return { valid: false, error: `Threshold (${threshold}) cannot exceed total channels count (${config.channels.length}).` };
    }

    for (let i = 0; i < config.channels.length; i++) {
      const ch = config.channels[i];
      if (!ch.plugin || typeof ch.plugin !== 'string') {
        return { valid: false, error: `Channel #${i + 1} is missing required "plugin" identifier.` };
      }
      if (!ch.config || typeof ch.config !== 'object') {
        return { valid: false, error: `Channel #${i + 1} is missing required "config" object.` };
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

    let secret = config.secret || config.payload;
    if (typeof secret === 'string' && secret.startsWith('ENV:')) {
      secret = process.env[secret.substring(4)] || '';
    }

    const totalShares = config.channels.length;
    const threshold = config.threshold || 2;

    if (context.dryRun) {
      return {
        success: true,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        output: {
          dryRun: true,
          totalShares,
          threshold,
          channels: config.channels.map((c: any) => c.plugin),
        },
      };
    }

    let shares: string[];
    try {
      shares = ShamirSecretSharing.split(secret, totalShares, threshold);
    } catch (err: any) {
      return {
        success: false,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        error: `Shamir split failed: ${err.message}`,
      };
    }

    const registry: PluginRegistry = (context as any).pluginRegistry || createDefaultPluginRegistry();
    const dispatchResults: Array<{ channelIndex: number; plugin: string; success: boolean; error?: string }> = [];

    for (let i = 0; i < totalShares; i++) {
      const channelDef = config.channels[i];
      const share = shares[i];
      const targetPlugin = registry.get(channelDef.plugin);

      if (!targetPlugin) {
        dispatchResults.push({
          channelIndex: i + 1,
          plugin: channelDef.plugin,
          success: false,
          error: `Plugin not found in registry: "${channelDef.plugin}"`,
        });
        continue;
      }

      const templateVars: Record<string, string> = {
        share,
        SHARE: share,
        shareIndex: String(i),
        shareNumber: String(i + 1),
        threshold: String(threshold),
        totalShares: String(totalShares),
      };

      const resolvedChannelConfig = this.injectShareVariables(channelDef.config, templateVars);

      try {
        const res = await targetPlugin.execute(resolvedChannelConfig, {
          ...context,
          actionId: `${context.actionId}-share-${i + 1}`,
        });

        dispatchResults.push({
          channelIndex: i + 1,
          plugin: channelDef.plugin,
          success: res.success,
          error: res.error,
        });
      } catch (err: any) {
        dispatchResults.push({
          channelIndex: i + 1,
          plugin: channelDef.plugin,
          success: false,
          error: err.message,
        });
      }
    }

    const hasFailures = dispatchResults.some(r => !r.success);

    return {
      success: !hasFailures,
      actionId: context.actionId,
      plugin: this.id,
      durationMs: Date.now() - startTime,
      error: hasFailures ? `One or more Shamir share dispatches failed (${dispatchResults.filter(r => !r.success).length}/${totalShares})` : undefined,
      output: {
        threshold,
        totalShares,
        channels: dispatchResults,
      },
    };
  }

  private injectShareVariables(obj: any, vars: Record<string, string>): any {
    if (typeof obj === 'string') {
      let res = obj;
      for (const [k, v] of Object.entries(vars)) {
        res = res.replaceAll(`{${k}}`, v).replaceAll(`\${${k}}`, v);
      }
      return res;
    }
    if (Array.isArray(obj)) {
      return obj.map(item => this.injectShareVariables(item, vars));
    }
    if (obj !== null && typeof obj === 'object') {
      const res: Record<string, any> = {};
      for (const [key, val] of Object.entries(obj)) {
        res[key] = this.injectShareVariables(val, vars);
      }
      return res;
    }
    return obj;
  }
}
