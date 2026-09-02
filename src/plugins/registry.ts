import { createHash } from 'node:crypto';
import type { IPluginExecutor } from './types.ts';
import { WebhookPlugin } from './core/webhook.ts';
import { DiscordPlugin } from './core/discord.ts';
import { TelegramPlugin } from './core/telegram.ts';
import { ShellPlugin } from './core/shell.ts';
import { EmailPlugin } from './core/email.ts';
import { S3Plugin } from './core/s3.ts';
import { GpgPlugin } from './core/gpg.ts';
import { NostrPlugin } from './core/nostr.ts';
import { NtfyPlugin } from './core/ntfy.ts';
import { MatrixPlugin } from './core/matrix.ts';
import { GotifyPlugin } from './core/gotify.ts';
import { SignalPlugin } from './core/signal.ts';
import { ShamirDistributePlugin } from './core/shamir-distribute.ts';

export class PluginRegistry {
  private plugins = new Map<string, IPluginExecutor>();

  public register(plugin: IPluginExecutor): void {
    this.plugins.set(plugin.id, plugin);
  }

  public get(id: string): IPluginExecutor | undefined {
    return this.plugins.get(id);
  }

  public has(id: string): boolean {
    return this.plugins.has(id);
  }

  public getPluginDigest(id: string): string {
    const plugin = this.plugins.get(id);
    if (!plugin) return '0000000000000000000000000000000000000000000000000000000000000000';
    if (typeof (plugin as any).getDigest === 'function') {
      return (plugin as any).getDigest();
    }
    return createHash('sha256')
      .update(`${plugin.id}:${plugin.version}:${plugin.name}:${plugin.riskTier || 'TRUSTED_CORE'}`)
      .digest('hex');
  }

  public list(): Array<{ id: string; name: string; description: string; version: string; digest: string }> {
    return Array.from(this.plugins.values()).map((p) => ({
      id: p.id,
      name: p.name,
      description: p.description,
      version: p.version,
      digest: this.getPluginDigest(p.id),
    }));
  }
}


export function createDefaultPluginRegistry(): PluginRegistry {
  const registry = new PluginRegistry();
  registry.register(new WebhookPlugin());
  registry.register(new DiscordPlugin());
  registry.register(new TelegramPlugin());
  registry.register(new ShellPlugin());
  registry.register(new EmailPlugin());
  registry.register(new S3Plugin());
  registry.register(new GpgPlugin());
  registry.register(new NostrPlugin());
  registry.register(new NtfyPlugin());
  registry.register(new MatrixPlugin());
  registry.register(new GotifyPlugin());
  registry.register(new SignalPlugin());
  registry.register(new ShamirDistributePlugin());
  return registry;
}
