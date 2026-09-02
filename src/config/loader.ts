import { parse as parseYaml } from 'yaml';
import { existsSync, readFileSync } from 'node:fs';
import type { OboldConfig, SwitchConfig, StageConfig, PluginActionConfig, ReminderConfig } from './types.ts';


export function parseDurationToMs(input: string | number): number {
  if (typeof input === 'number') {
    return input;
  }

  const trimmed = input.trim().toLowerCase();
  if (/^\d+$/.test(trimmed)) {
    return parseInt(trimmed, 10);
  }

  const match = trimmed.match(/^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w|y)$/);
  if (!match) {
    throw new Error(`Invalid duration format: "${input}". Expected examples: "30d", "48h", "15m", "30s", "500ms".`);
  }

  const value = parseFloat(match[1]);
  const unit = match[2];

  switch (unit) {
    case 'ms':
      return Math.round(value);
    case 's':
      return Math.round(value * 1000);
    case 'm':
      return Math.round(value * 60 * 1000);
    case 'h':
      return Math.round(value * 60 * 60 * 1000);
    case 'd':
      return Math.round(value * 24 * 60 * 60 * 1000);
    case 'w':
      return Math.round(value * 7 * 24 * 60 * 60 * 1000);
    case 'y':
      return Math.round(value * 365 * 24 * 60 * 60 * 1000);
    default:
      throw new Error(`Unsupported duration unit: ${unit}`);
  }
}


export function formatMsToDuration(ms: number): string {
  if (ms < 0) return '0s';
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) {
    const remHours = hours % 24;
    return remHours > 0 ? `${days}d ${remHours}h` : `${days}d`;
  }
  if (hours > 0) {
    const remMinutes = minutes % 60;
    return remMinutes > 0 ? `${hours}h ${remMinutes}m` : `${hours}h`;
  }
  if (minutes > 0) {
    const remSeconds = seconds % 60;
    return remSeconds > 0 ? `${minutes}m ${remSeconds}s` : `${minutes}m`;
  }
  return `${seconds}s`;
}


export const DEFAULT_CONFIG: OboldConfig = {
  version: '1.0.0',
  organization: 'BCN Studio',
  storage: {
    path: './data/obold.db',
    walMode: true,
    autoCheckpointIntervalMs: 60000,
  },
  crypto: {
    algorithm: 'chacha20-poly1305',
    keyDerivation: 'scrypt',
  },
  server: {
    enabled: true,
    host: '127.0.0.1',
    port: 8080,
  },
  switches: [],
  logLevel: 'INFO',
};


export function resolveEnvPlaceholders(value: any, customEnv: Record<string, string | undefined> = process.env): any {
  if (value === null || value === undefined) {
    return value;
  }

  if (typeof value === 'string') {
    if (value.startsWith('ENV:')) {
      const varName = value.substring(4).trim();
      return customEnv[varName] !== undefined ? customEnv[varName] : '';
    }

    if (value.startsWith('${REQUIRED:') && value.endsWith('}')) {
      const varName = value.substring(11, value.length - 1).trim();
      const val = customEnv[varName];
      if (val === undefined || val.trim() === '') {
        throw new Error(`Required environment variable "${varName}" is missing or empty.`);
      }
      return val;
    }

    return value.replace(/\$\{([A-Za-z0-9_:]+)(?::-([^}]*))?\}|\$([A-Za-z0-9_]+)/g, (match, var1, defVal, var2) => {
      if (var1) {
        if (var1.startsWith('REQUIRED:')) {
          const reqName = var1.substring(9).trim();
          const reqVal = customEnv[reqName];
          if (reqVal === undefined || reqVal.trim() === '') {
            throw new Error(`Required environment variable "${reqName}" is missing or empty.`);
          }
          return reqVal;
        }

        const val = customEnv[var1];
        if (val !== undefined && val !== '') {
          return val;
        }
        if (defVal !== undefined) {
          return defVal;
        }
        return val !== undefined ? val : '';
      }
      if (var2) {
        const val = customEnv[var2];
        return val !== undefined ? val : '';
      }
      return match;
    });
  }

  if (Array.isArray(value)) {
    return value.map((item) => resolveEnvPlaceholders(item, customEnv));
  }

  if (typeof value === 'object') {
    const result: Record<string, any> = {};
    for (const [k, v] of Object.entries(value)) {
      result[k] = resolveEnvPlaceholders(v, customEnv);
    }
    return result;
  }

  return value;
}

export function normalizeAndValidateConfig(rawInput: any): OboldConfig {
  if (!rawInput || typeof rawInput !== 'object') {
    throw new Error('Config file must contain a top-level object.');
  }

  const raw = resolveEnvPlaceholders(rawInput);

  const rawHost = raw.server?.host || DEFAULT_CONFIG.server.host;
  const isLoopback = rawHost === '127.0.0.1' || rawHost === 'localhost' || rawHost === '::1' || rawHost === '127.0.0.0' || rawHost === 'localhost.localdomain';
  const serverEnabled = raw.server?.enabled !== false;
  const apiAuthToken = raw.server?.apiAuthToken ? String(raw.server.apiAuthToken).trim() : undefined;
  const corsOrigins = Array.isArray(raw.server?.corsOrigins) ? raw.server.corsOrigins : undefined;

  if (serverEnabled && !isLoopback) {
    if (!apiAuthToken || apiAuthToken === '') {
      throw new Error(`Refusing remote host binding ("${rawHost}") without apiAuthToken. Non-loopback host binding requires mandatory authentication.`);
    }
    if (corsOrigins && corsOrigins.includes('*')) {
      throw new Error(`Refusing remote host binding ("${rawHost}") with wildcard CORS origin ('*'). Remote deployments must configure explicit trusted origins.`);
    }
  }

  const config: OboldConfig = {
    version: raw.version || DEFAULT_CONFIG.version,
    organization: raw.organization || DEFAULT_CONFIG.organization,
    storage: {
      path: raw.storage?.path || DEFAULT_CONFIG.storage.path,
      walMode: raw.storage?.walMode !== false,
      autoCheckpointIntervalMs: raw.storage?.autoCheckpointIntervalMs
        ? parseDurationToMs(raw.storage.autoCheckpointIntervalMs)
        : DEFAULT_CONFIG.storage.autoCheckpointIntervalMs,
    },
    crypto: {
      algorithm: raw.crypto?.algorithm || DEFAULT_CONFIG.crypto.algorithm,
      keyDerivation: raw.crypto?.keyDerivation || DEFAULT_CONFIG.crypto.keyDerivation,
      salt: raw.crypto?.salt,
    },
    server: {
      enabled: serverEnabled,
      host: rawHost,
      port: raw.server?.port || DEFAULT_CONFIG.server.port,
      apiAuthToken,
      corsOrigins,
      trustedProxies: Array.isArray(raw.server?.trustedProxies) ? raw.server.trustedProxies : undefined,
      allowRemoteCryptoApi: raw.server?.allowRemoteCryptoApi === true,
      publicHealth: raw.server?.publicHealth !== false,
      publicCheckin: raw.server?.publicCheckin !== false,
      publicMetrics: raw.server?.publicMetrics === true,
      publicEvents: raw.server?.publicEvents === true,
    },
    switches: [],
    logLevel: raw.logLevel || DEFAULT_CONFIG.logLevel,
  };

  const rawSwitches = Array.isArray(raw.switches) ? raw.switches : [];
  const switchIds = new Set<string>();

  for (const s of rawSwitches) {
    if (!s.id || typeof s.id !== 'string') {
      throw new Error('Each switch must have a unique "id" string.');
    }
    if (switchIds.has(s.id)) {
      throw new Error(`Duplicate switch id detected: "${s.id}". Switch IDs must be unique.`);
    }
    switchIds.add(s.id);

    const intervalMs = parseDurationToMs(s.interval ?? '30d');
    const gracePeriodMs = parseDurationToMs(s.gracePeriod ?? '48h');

    const reminders: ReminderConfig[] = [];
    if (Array.isArray(s.reminders)) {
      for (const r of s.reminders) {
        reminders.push({
          id: r.id || `rem-${Math.random().toString(36).substring(2, 7)}`,
          name: r.name || 'Check-in Reminder',
          beforeMs: parseDurationToMs(r.before ?? '24h'),
          plugin: r.plugin || 'core:email',
          config: r.config || {},
        });
      }
    }

    const stages: StageConfig[] = [];
    if (Array.isArray(s.stages)) {
      for (let i = 0; i < s.stages.length; i++) {
        const stage = s.stages[i];
        const actions: PluginActionConfig[] = [];

        if (Array.isArray(stage.actions)) {
          for (const a of stage.actions) {
            if (!a.plugin) {
              throw new Error(`Action in switch "${s.id}", stage "${stage.id || i}" missing required "plugin" property.`);
            }
            actions.push({
              id: a.id || `act-${Math.random().toString(36).substring(2, 7)}`,
              plugin: a.plugin,
              name: a.name || a.plugin,
              description: a.description,
              config: a.config || {},
              timeoutMs: a.timeout ? parseDurationToMs(a.timeout) : 30000,
              continueOnError: a.continueOnError !== false,
              dependsOn: a.dependsOn || [],
            });
          }
        }

        stages.push({
          id: stage.id || `stage-${i + 1}`,
          name: stage.name || `Stage ${i + 1}`,
          delayMs: stage.delay ? parseDurationToMs(stage.delay) : 0,
          description: stage.description,
          actions,
        });
      }
    }

    const sw: SwitchConfig = {
      id: s.id,
      name: s.name || s.id,
      description: s.description,
      enabled: s.enabled !== false,
      intervalMs,
      gracePeriodMs,
      reminders,
      stages,
      tags: s.tags || [],
    };

    if (s.duress) {
      sw.duress = {
        enabled: s.duress.enabled !== false,
        pin: s.duress.pin,
        actions: Array.isArray(s.duress.actions)
          ? s.duress.actions.map((a: any) => ({
              id: a.id || `duress-act-${Math.random().toString(36).substring(2, 7)}`,
              plugin: a.plugin,
              name: a.name || 'Duress Alert',
              config: a.config || {},
              timeoutMs: 15000,
              continueOnError: true,
            }))
          : [],
      };
    }

    config.switches.push(sw);
  }

  return config;
}


export function loadConfigFile(filePath: string): OboldConfig {
  if (!existsSync(filePath)) {
    throw new Error(`Configuration file not found at: ${filePath}`);
  }

  const content = readFileSync(filePath, 'utf-8');
  let parsed: any;

  if (filePath.endsWith('.json')) {
    try {
      parsed = JSON.parse(content);
    } catch (err: any) {
      throw new Error(`JSON Syntax Error in ${filePath}: ${err.message}`);
    }
  } else {
    try {
      parsed = parseYaml(content);
    } catch (err: any) {
      throw new Error(`YAML Syntax Error in ${filePath}: ${err.message}`);
    }
  }

  return normalizeAndValidateConfig(parsed);
}


export function generateStarterYamlTemplate(): string {
  return `version: "1.0.0"
organization: "BCN Studio"
logLevel: "INFO"

storage:
  path: "./data/obold.db"
  walMode: true
  autoCheckpointIntervalMs: "1m"

crypto:
  algorithm: "chacha20-poly1305"
  keyDerivation: "scrypt"

server:
  enabled: true
  host: "127.0.0.1"
  port: 8080

switches:
  - id: "primary-vault"
    name: "Primary Digital Inheritance & Server Switch"
    description: "Multi-stage dead man's switch triggered if no check-in is received within 30 days."
    enabled: true
    interval: "30d"
    gracePeriod: "48h"

    reminders:
      - id: "warn-7d"
        name: "7-Day Check-in Warning"
        before: "7d"
        plugin: "core:webhook"
        config:
          target_url: "https://api.example.com/notifications/deadmanswitch"
          http_method: "POST"
          json_body:
            message: "obold: 7 days remaining to check in."

      - id: "warn-24h"
        name: "24-Hour Urgent Alert"
        before: "24h"
        plugin: "core:discord"
        config:
          webhook_url: "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL"
          content: "URGENT: obold check-in required within 24 hours."

    stages:
      - id: "stage-1"
        name: "Soft Alert to Trusted Contacts"
        delay: "0s"
        actions:
          - id: "email-family"
            plugin: "core:email"
            name: "Notify Family"
            config:
              smtp_host: "smtp.mailgun.org"
              smtp_port: 587
              smtp_user: "postmaster@example.com"
              smtp_pass: "ENV:SMTP_PASSWORD"
              from: "obold-daemon@example.com"
              to: ["trusted-contact@example.com"]
              subject: "obold: Automated Status Notification"
              body: "This is an automated status notice from obold daemon."

      - id: "stage-2"
        name: "Digital Asset Release & Decryption"
        delay: "48h"
        actions:
          - id: "webhook-vault-release"
            plugin: "core:webhook"
            name: "Trigger Cloud Custodian Release"
            config:
              target_url: "https://api.vault.example.com/emergency-release"
              http_method: "POST"
              headers:
                Authorization: "Bearer ENV:VAULT_API_TOKEN"
              json_body:
                action: "release_emergency_key"

      - id: "stage-3"
        name: "Host Cleanup & Key Shredder"
        delay: "72h"
        actions:
          - id: "shred-local-keys"
            plugin: "core:shell"
            name: "Shred Ephemeral Host Keys"
            config:
              command: "echo 'Executing final host cleanup protocol...'"
              timeout_ms: 10000

    duress:
      enabled: true
      pin: "9999"
      actions:
        - id: "duress-silent-beacon"
          plugin: "core:webhook"
          name: "Silent Distress Beacon"
          config:
            target_url: "https://api.security.example.com/duress-alert"
            http_method: "POST"
            json_body:
              alert: "DURESS_TRIGGERED"
`;
}
