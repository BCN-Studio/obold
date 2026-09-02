import { describe, test, expect } from 'bun:test';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { schnorr } from '@noble/curves/secp256k1.js';
import { EmailPlugin } from '../src/plugins/core/email.ts';
import { NostrPlugin } from '../src/plugins/core/nostr.ts';
import { WebhookPlugin } from '../src/plugins/core/webhook.ts';
import { ShellPlugin } from '../src/plugins/core/shell.ts';
import { validateWebSocketUrl } from '../src/plugins/network-guard.ts';
import { normalizeAndValidateConfig, generateStarterYamlTemplate } from '../src/config/loader.ts';
import { OboldDatabase } from '../src/db/database.ts';
import { OboldCipher } from '../src/crypto/cipher.ts';
import { PluginRegistry } from '../src/plugins/registry.ts';
import { OboldEngine } from '../src/core/engine.ts';
import type { OboldConfig } from '../src/config/types.ts';

describe('Plugins & Cryptographic Protocols Verification', () => {
  test('EmailPlugin: rejects newline injection in headers and validates required environment variables', () => {
    const plugin = new EmailPlugin();

    const newlineSubject = plugin.validateConfig({
      smtp_host: 'smtp.example.com',
      to: ['recipient@example.com'],
      subject: 'Injected\r\nBcc: evil@attacker.com',
    });
    expect(newlineSubject.valid).toBe(false);
    expect(newlineSubject.error).toContain('newline characters are forbidden');

    const newlineFrom = plugin.validateConfig({
      smtp_host: 'smtp.example.com',
      from: 'admin@example.com\r\nSubject: Overridden',
      to: ['recipient@example.com'],
      subject: 'Valid Subject',
    });
    expect(newlineFrom.valid).toBe(false);
    expect(newlineFrom.error).toContain('newline characters are forbidden');

    const missingEnvUser = plugin.validateConfig({
      smtp_host: 'smtp.example.com',
      to: ['recipient@example.com'],
      subject: 'Valid Subject',
      smtp_user: 'ENV:NON_EXISTENT_SMTP_USER_12345',
    });
    expect(missingEnvUser.valid).toBe(false);
    expect(missingEnvUser.error).toContain('Missing required environment variable');

    const invalidPort = plugin.validateConfig({
      smtp_host: 'smtp.example.com',
      to: ['recipient@example.com'],
      subject: 'Valid Subject',
      smtp_port: 999999,
    });
    expect(invalidPort.valid).toBe(false);
    expect(invalidPort.error).toContain('must be a valid port number');
  });

  test('EmailPlugin: executes dry-run safely without network connection', async () => {
    const plugin = new EmailPlugin();
    const result = await plugin.execute(
      {
        smtp_host: 'smtp.example.com',
        to: ['recipient@example.com'],
        subject: 'Dry Run Alert',
      },
      {
        switchId: 'test-sw',
        switchName: 'Test Switch',
        stageId: 'stage-1',
        actionId: 'act-email',
        dryRun: true,
        deadlineAt: Date.now() + 60000,
      }
    );

    expect(result.success).toBe(true);
    expect(result.output?.dryRun).toBe(true);
    expect(result.output?.host).toBe('smtp.example.com');
  });

  test('NostrPlugin: validates 64-character secp256k1 private keys and rejects empty or zero signatures', () => {
    const plugin = new NostrPlugin();

    const missingKey = plugin.validateConfig({
      relays: ['wss://relay.damus.io'],
      content: 'Dead man switch warning',
    });
    expect(missingKey.valid).toBe(false);
    expect(missingKey.error).toContain('private_key');

    const invalidHex = plugin.validateConfig({
      relays: ['wss://relay.damus.io'],
      content: 'Dead man switch warning',
      private_key: 'not-a-valid-hex-string',
    });
    expect(invalidHex.valid).toBe(false);
    expect(invalidHex.error).toContain('64 hexadecimal characters');

    const validKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const validConfig = plugin.validateConfig({
      relays: ['wss://relay.damus.io'],
      content: 'Dead man switch warning',
      private_key: validKey,
    });
    expect(validConfig.valid).toBe(true);
  });

  test('NostrPlugin: generates authentic BIP-340 Schnorr signature over secp256k1', async () => {
    const plugin = new NostrPlugin();
    const privKeyHex = 'e8f00123456789abcdef0123456789abcdef0123456789abcdef0123456789ab';
    const privBytes = Uint8Array.from(Buffer.from(privKeyHex, 'hex'));
    const expectedPub = Buffer.from(schnorr.getPublicKey(privBytes)).toString('hex');

    const dryRunResult = await plugin.execute(
      {
        relays: ['wss://relay.damus.io'],
        content: 'Emergency notification test',
        private_key: privKeyHex,
      },
      {
        switchId: 'sw-nostr',
        switchName: 'Nostr Switch',
        stageId: 'stage-1',
        actionId: 'act-nostr',
        dryRun: true,
        deadlineAt: Date.now() + 60000,
      }
    );

    expect(dryRunResult.success).toBe(true);
    expect(dryRunResult.output?.dryRun).toBe(true);

    const createdAt = Math.floor(Date.now() / 1000);
    const content = 'Emergency notification test';
    const serialized = JSON.stringify([0, expectedPub, createdAt, 1, [['t', 'obold']], content]);
    const eventId = createHash('sha256').update(serialized).digest('hex');
    const sigBytes = schnorr.sign(Uint8Array.from(Buffer.from(eventId, 'hex')), privBytes);
    const isValid = schnorr.verify(sigBytes, Uint8Array.from(Buffer.from(eventId, 'hex')), schnorr.getPublicKey(privBytes));
    expect(isValid).toBe(true);
  });

  test('validateWebSocketUrl: blocks loopback and private IPv4/IPv6 SSRF destinations', async () => {
    const loopback = await validateWebSocketUrl('ws://127.0.0.1:8080', false);
    expect(loopback.valid).toBe(false);
    expect(loopback.error).toContain('Blocked');

    const localhost = await validateWebSocketUrl('ws://localhost:9000', false);
    expect(localhost.valid).toBe(false);
    expect(localhost.error).toContain('Blocked');

    const invalidProto = await validateWebSocketUrl('http://relay.example.com', false);
    expect(invalidProto.valid).toBe(false);
    expect(invalidProto.error).toContain('Only ws:// and wss://');

    const allowed = await validateWebSocketUrl('ws://127.0.0.1:8080', true);
    expect(allowed.valid).toBe(true);
  });

  test('WebhookPlugin: binds timestamp into cryptographic HMAC signature for replay protection', async () => {
    const plugin = new WebhookPlugin();
    const secret = 'super-secret-webhook-key';

    const dryResult = await plugin.execute(
      {
        target_url: 'https://api.example.com/webhook',
        signing_secret: secret,
      },
      {
        switchId: 'sw-webhook',
        switchName: 'Webhook Switch',
        stageId: 'stage-1',
        actionId: 'act-wh',
        dryRun: true,
        deadlineAt: Date.now() + 60000,
      }
    );

    expect(dryResult.success).toBe(true);
    expect(dryResult.output?.dryRun).toBe(true);

    const timestamp = Date.now().toString();
    const bodyStr = JSON.stringify({ event: 'test' });
    const expectedSig = createHmac('sha256', secret).update(`${timestamp}.${bodyStr}`).digest('hex');
    expect(expectedSig.length).toBe(64);
  });

  test('ShellPlugin: terminates child process subtree cleanly on timeout', async () => {
    const plugin = new ShellPlugin();
    const start = Date.now();
    const result = await plugin.execute(
      {
        command: process.platform === 'win32' ? 'powershell -Command Start-Sleep -Seconds 10' : 'sleep 10',
        timeout_ms: 300,
      },
      {
        switchId: 'sw-shell',
        switchName: 'Shell Switch',
        stageId: 'stage-1',
        actionId: 'act-shell',
        dryRun: false,
        deadlineAt: Date.now() + 60000,
      }
    );

    const elapsed = Date.now() - start;
    expect(result.success).toBe(false);
    expect(result.error).toContain('timed out after 300ms');
    expect(elapsed).toBeLessThan(4000);
  });

  test('Config Loader: generates UUID action IDs and supports schemaVersion 1', () => {
    const rawYaml = `
schemaVersion: 1
version: "1.0.0-beta"
switches:
  - id: "sw-uuid"
    interval: "1h"
    stages:
      - actions:
          - plugin: "core:shell"
            command: "echo 1"
    duress:
      actions:
        - plugin: "core:shell"
          command: "echo duress"
`;
    const config = normalizeAndValidateConfig(require('yaml').parse(rawYaml));
    expect(config.schemaVersion).toBe(1);
    expect(config.switches[0].stages[0].actions[0].id).toMatch(/^act-[0-9a-fA-F-]{36}$/);
    expect(config.switches[0].duress?.actions[0].id).toMatch(/^duress-act-[0-9a-fA-F-]{36}$/);

    const starterTemplate = generateStarterYamlTemplate();
    expect(starterTemplate).toContain('schemaVersion: 1');
    expect(starterTemplate).toContain('version: "1.0.0-beta"');
  });

  test('Engine: execution contracts include dynamic software provenance digests and hashes', async () => {
    const db = new OboldDatabase(':memory:', false);
    const cipher = new OboldCipher(randomBytes(32).toString('hex'));
    const registry = new PluginRegistry();
    registry.register(new ShellPlugin());

    const config: OboldConfig = {
      version: '1.0.0-beta',
      schemaVersion: 1,
      storage: { path: ':memory:', walMode: false },
      crypto: { algorithm: 'chacha20-poly1305', keyDerivation: 'scrypt' },
      server: { enabled: false, host: '127.0.0.1', port: 8080 },
      switches: [
        {
          id: 'sw-prov',
          name: 'Provenance Switch',
          version: 2,
          enabled: true,
          intervalMs: 3600000,
          gracePeriodMs: 60000,
          stages: [
            {
              id: 'stage-prov',
              name: 'Prov Stage',
              delayMs: 0,
              actions: [
                {
                  id: 'act-prov-1',
                  plugin: 'core:shell',
                  config: { command: 'echo provenance' },
                },
              ],
            },
          ],
        },
      ],
    };

    const engine = new OboldEngine(config, db, cipher, registry);
    const triggerResult = await engine.triggerSwitch('sw-prov', true);
    expect(triggerResult.status).toBe('COMPLETED');
    expect(triggerResult.results?.[0].success).toBe(true);
    const rows = db.getRecentLedgerEntries(5);
    expect(rows.length).toBeGreaterThan(0);

    cipher.destroy();
    db.close();
  });
});
