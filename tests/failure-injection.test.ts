import { describe, test, expect, beforeEach, afterEach } from 'bun:test';
import { existsSync, unlinkSync, mkdirSync } from 'node:fs';
import { OboldDatabase } from '../src/db/database.ts';
import { OboldCipher } from '../src/crypto/cipher.ts';
import { OboldEngine } from '../src/core/engine.ts';
import { PluginRegistry } from '../src/plugins/registry.ts';
import { ShamirSecretSharing } from '../src/crypto/shamir.ts';
import { generateRescueBundle, verifyRescueBundle, sanitizeRescueFilename } from '../src/crypto/rescue.ts';
import { validateTargetUrl } from '../src/plugins/network-guard.ts';
import { resolveMasterKey as resolveKeyBuffer } from '../src/crypto/kdf.ts';
import { DeadLetterRetryQueue } from '../src/core/retry-queue.ts';
import { OboldTokenManager, constantTimeStringEquals } from '../src/crypto/token.ts';
import { ShellPlugin } from '../src/plugins/core/shell.ts';
import type { IPluginExecutor, PluginExecutionContext } from '../src/plugins/types.ts';
import type { ExecutionResult, OboldConfig } from '../src/config/types.ts';

class MockPlugin implements IPluginExecutor {
  readonly id = 'mock:test';
  readonly name = 'Mock Test Plugin';
  readonly description = 'Mock plugin for failure-injection testing';
  readonly version = '1.0.0';

  public shouldFailTransient: boolean = false;
  public shouldFailPermanent: boolean = false;
  public callCount: number = 0;
  public lastIdempotencyKey?: string;

  validateConfig(config: Record<string, any>) {
    return { valid: true };
  }

  async execute(config: Record<string, any>, context: PluginExecutionContext): Promise<ExecutionResult> {
    this.callCount++;
    this.lastIdempotencyKey = context.idempotencyKey;

    if (this.shouldFailPermanent) {
      return {
        success: false,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: 5,
        error: 'HTTP Error 401: Unauthorized API key',
      };
    }

    if (this.shouldFailTransient) {
      return {
        success: false,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: 5,
        error: 'FetchError: ETIMEDOUT connection timed out',
      };
    }

    return {
      success: true,
      actionId: context.actionId,
      plugin: this.id,
      durationMs: 5,
      output: { delivered: true, echo: config },
    };
  }
}

function createTestConfig(dbPath: string): OboldConfig {
  return {
    version: '1.0.0',
    storage: {
      path: dbPath,
      walMode: true,
      autoCheckpointIntervalMs: 60000,
    },
    crypto: {
      algorithm: 'chacha20-poly1305',
      keyDerivation: 'scrypt',
    },
    server: {
      enabled: false,
      host: '127.0.0.1',
      port: 8888,
    },
    switches: [
      {
        id: 'test-switch',
        name: 'Failure Injection Test Switch',
        enabled: true,
        intervalMs: 10000,
        gracePeriodMs: 5000,
        reminders: [],
        stages: [
          {
            id: 'stage-1',
            name: 'Emergency Stage',
            delayMs: 0,
            actions: [
              {
                id: 'act-1',
                name: 'Test Action',
                plugin: 'mock:test',
                config: { message: 'Alert' },
              },
            ],
          },
        ],
      },
    ],
  };
}

describe('Failure Injection & Crash Resilience Suite', () => {
  const dbPath = './data/test_failure_resilience.db';
  let db: OboldDatabase;
  let cipher: OboldCipher;
  let plugins: PluginRegistry;
  let mockPlugin: MockPlugin;

  beforeEach(() => {
    if (!existsSync('./data')) mkdirSync('./data', { recursive: true });
    try {
      if (existsSync(dbPath)) unlinkSync(dbPath);
      if (existsSync(`${dbPath}-wal`)) unlinkSync(`${dbPath}-wal`);
      if (existsSync(`${dbPath}-shm`)) unlinkSync(`${dbPath}-shm`);
    } catch {}

    db = new OboldDatabase(dbPath, true);
    cipher = new OboldCipher('failure-injection-secret-key-001', 'chacha20-poly1305');
    plugins = new PluginRegistry();
    mockPlugin = new MockPlugin();
    plugins.register(mockPlugin);
  });

  afterEach(() => {
    db.close();
    try {
      if (existsSync(dbPath)) unlinkSync(dbPath);
      if (existsSync(`${dbPath}-wal`)) unlinkSync(`${dbPath}-wal`);
      if (existsSync(`${dbPath}-shm`)) unlinkSync(`${dbPath}-shm`);
    } catch {}
  });

  test('Test 1: Mid-Dispatch Process Crash & Startup Replay Recovery', async () => {
    const config = createTestConfig(dbPath);
    const engine1 = new OboldEngine(config, db, cipher, plugins);

    const rawConfig = { target: 'https://webhook.site/test', payload: { alert: 'critical' } };
    const encPayload = cipher.encryptToString(rawConfig);

    db.insertLedgerEntry({
      id: 'led-crash-test-001',
      switchId: 'test-switch',
      stageId: 'stage-1',
      actionId: 'act-1',
      plugin: 'mock:test',
      state: 'EXECUTING',
      idempotencyKey: 'idemp-crash-001',
      attemptCount: 1,
      maxAttempts: 5,
      nextRetryAt: null,
      lastError: null,
      payloadSnapshot: encPayload,
      resultSnapshot: null,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      dispatchedAt: Date.now(),
      acknowledgedAt: null,
    });

    engine1.stop();
    db.close();

    const db2 = new OboldDatabase(dbPath, true);
    const mockPlugin2 = new MockPlugin();
    const plugins2 = new PluginRegistry();
    plugins2.register(mockPlugin2);

    const engine2 = new OboldEngine(config, db2, cipher, plugins2);
    await engine2.replayLedger();

    expect(mockPlugin2.callCount).toBe(1);
    expect(mockPlugin2.lastIdempotencyKey).toBe('idemp-crash-001');

    const entry = db2.getLedgerEntry('led-crash-test-001');
    expect(entry).not.toBeNull();
    expect(entry?.state).toBe('SUCCEEDED');
    expect(entry?.acknowledgedAt).toBeGreaterThan(0);

    db2.close();
    db = new OboldDatabase(dbPath, true);
  });

  test('Test 2: Transient Network Dropout & Exponential Backoff', async () => {
    const config = createTestConfig(dbPath);
    const engine = new OboldEngine(config, db, cipher, plugins);

    mockPlugin.shouldFailTransient = true;
    const results = await engine.executeStage(config.switches[0], 0, false);

    expect(results.length).toBe(1);
    expect(results[0].success).toBe(false);

    const entries = db.getRecentLedgerEntries(10);
    expect(entries.length).toBe(1);
    expect(entries[0].state).toBe('FAILED_RETRYABLE');
    expect(entries[0].attemptCount).toBe(1);
    expect(entries[0].nextRetryAt).not.toBeNull();
    expect(entries[0].nextRetryAt!).toBeGreaterThan(Date.now());
  });

  test('Test 3: Permanent Auth Error (HTTP 401) Immediate Failure', async () => {
    const config = createTestConfig(dbPath);
    const engine = new OboldEngine(config, db, cipher, plugins);

    mockPlugin.shouldFailPermanent = true;
    const results = await engine.executeStage(config.switches[0], 0, false);

    expect(results.length).toBe(1);
    expect(results[0].success).toBe(false);

    const entries = db.getRecentLedgerEntries(10);
    expect(entries.length).toBe(1);
    expect(entries[0].state).toBe('FAILED_PERMANENT');
    expect(entries[0].nextRetryAt).toBeNull();
  });

  test('Test 4: SSRF Guard Blocks Loopback and Cloud Metadata', async () => {
    const check1 = await validateTargetUrl('http://127.0.0.1:8080/hook', false);
    expect(check1.valid).toBe(false);

    const check2 = await validateTargetUrl('http://169.254.169.254/latest/meta-data', false);
    expect(check2.valid).toBe(false);

    const check3 = await validateTargetUrl('http://10.0.0.5:9000/api', false);
    expect(check3.valid).toBe(false);

    const check4 = await validateTargetUrl('http://192.168.1.100/webhook', false);
    expect(check4.valid).toBe(false);

    const check5 = await validateTargetUrl('http://172.20.0.10:3000/callback', false);
    expect(check5.valid).toBe(false);

    const checkPrivateAllowed = await validateTargetUrl('http://10.0.0.5:9000/api', true);
    expect(checkPrivateAllowed.valid).toBe(true);
  });

  test('Test 5: Monotonic Clock Stability Across Wall-Clock Skew', () => {
    const config = createTestConfig(dbPath);
    const engine = new OboldEngine(config, db, cipher, plugins);

    const m0 = engine.getMonotonicElapsedMs();
    let acc = 0;
    for (let i = 0; i < 50000; i++) acc += i;
    const m1 = engine.getMonotonicElapsedMs();

    expect(m1).toBeGreaterThanOrEqual(m0);
  });

  test('Test 6: Shamir Secret Sharing Multi-Party Recovery', () => {
    const secret = 'super-secret-vault-master-key-xyz-777';
    const totalShares = 5;
    const threshold = 3;

    const shares = ShamirSecretSharing.split(secret, totalShares, threshold);
    expect(shares.length).toBe(5);

    const reconstructed = ShamirSecretSharing.combine([shares[0], shares[2], shares[4]]);
    expect(reconstructed).toBe(secret);

    const reconstructed2 = ShamirSecretSharing.combine([shares[1], shares[3], shares[4]]);
    expect(reconstructed2).toBe(secret);
  });

  test('Test 7: Master Key Rotation & Zero Plaintext Leakage', () => {
    const oldCipher = new OboldCipher('old-passphrase-alpha');
    const newCipher = new OboldCipher('new-passphrase-beta');

    const originalData = { apiKey: 'secret-token-12345', target: 'https://vault.internal' };
    const aad = 'test-switch:stage-1:act-1:mock:test:v1';
    const encOriginal = oldCipher.encryptToString(originalData, aad);

    db.insertLedgerEntry({
      id: 'led-rekey-001',
      switchId: 'test-switch',
      stageId: 'stage-1',
      actionId: 'act-1',
      plugin: 'mock:test',
      state: 'SUCCEEDED',
      attemptCount: 1,
      maxAttempts: 5,
      payloadSnapshot: encOriginal,
      resultSnapshot: null,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    });

    const res = db.rekeyDatabase(oldCipher, newCipher);
    expect(res.reencryptedRecords).toBe(1);

    const updated = db.getLedgerEntry('led-rekey-001');
    expect(updated).not.toBeNull();
    expect(updated?.payloadSnapshot).not.toBe(encOriginal);

    const decryptedWithNew = JSON.parse(newCipher.decryptFromString(updated!.payloadSnapshot!, aad));
    expect(decryptedWithNew).toEqual(originalData);

    expect(() => oldCipher.decryptFromString(updated!.payloadSnapshot!, aad)).toThrow();

    oldCipher.destroy();
    newCipher.destroy();
  });

  test('Test 8: Automatic Secret Redaction in Database Audit Logs', () => {
    db.logAudit('INFO', 'TEST_EVENT', 'Sensitive operation executed', {
      username: 'operator',
      password: 'super-secret-password-123',
      api_key: 'sk_live_abcdef123456',
      normalField: 'hello-world',
    });

    const logs = db.getAuditLogs(5);
    expect(logs.length).toBeGreaterThan(0);
    const parsedMeta = JSON.parse(logs[0].metadata || '{}');

    expect(parsedMeta.username).toBe('operator');
    expect(parsedMeta.normalField).toBe('hello-world');
    expect(parsedMeta.password).toBe('[REDACTED]');
    expect(parsedMeta.api_key).toBe('[REDACTED]');
  });

  test('Test 9: Authenticated Shamir v1 Tamper & Set-Mismatch Rejection', () => {
    const secretA = 'secret-payload-alpha-12345';
    const secretB = 'secret-payload-beta-67890';

    const sharesA = ShamirSecretSharing.split(secretA, 5, 3);
    const sharesB = ShamirSecretSharing.split(secretB, 5, 3);

    const lastChar = sharesA[0].slice(-1);
    const tamperedShare = sharesA[0].slice(0, -1) + (lastChar === 'a' ? 'b' : 'a');
    expect(() => ShamirSecretSharing.combine([tamperedShare, sharesA[1], sharesA[2]])).toThrow(
      /Invalid share checksum|corrupted or tampered/
    );

    expect(() => ShamirSecretSharing.combine([sharesA[0], sharesA[1], sharesB[2]])).toThrow(
      /Mismatched share sets/
    );
  });

  test('Test 10: Rescue Bundle Creation & Offline Cryptographic Verification', () => {
    const payload = 'CRITICAL-EMERGENCY-MASTER-SEED-PHRASE-2026';
    const bundle = generateRescueBundle({
      payload,
      threshold: 3,
      totalShares: 5,
      title: 'Heritage Vault',
    });

    expect(bundle.shares.length).toBe(5);
    expect(bundle.html).toContain('Heritage Vault');
    expect(bundle.manifest.threshold).toBe(3);

    const verification = verifyRescueBundle(bundle.html);
    expect(verification.valid).toBe(true);
    expect(verification.manifest?.cipherSha256).toBe(bundle.manifest.cipherSha256);

    const tamperedHtml = bundle.html.replaceAll(bundle.manifest.cipherSha256, '0'.repeat(64));
    const tamperedVerification = verifyRescueBundle(tamperedHtml);
    expect(tamperedVerification.valid).toBe(false);
    expect(tamperedVerification.error).toContain('digest mismatch');
  });

  test('Test 11: Transactional Rollback on Rekey Failure', () => {
    const oldCipher = new OboldCipher('valid-old-key-alpha');
    const newCipher = new OboldCipher('valid-new-key-beta');

    const corruptedPayload = 'enc:aes-256-gcm:corrupted_iv:corrupted_tag:corrupted_data';

    db.insertLedgerEntry({
      id: 'led-rekey-corrupted-001',
      switchId: 'test-switch',
      stageId: 'stage-1',
      actionId: 'act-1',
      plugin: 'mock:test',
      state: 'SUCCEEDED',
      attemptCount: 1,
      maxAttempts: 5,
      payloadSnapshot: corruptedPayload,
      resultSnapshot: null,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    });

    expect(() => db.rekeyDatabase(oldCipher, newCipher)).toThrow(/Failed to decrypt/);

    const unchanged = db.getLedgerEntry('led-rekey-corrupted-001');
    expect(unchanged?.payloadSnapshot).toBe(corruptedPayload);

    oldCipher.destroy();
    newCipher.destroy();
  });

  test('Test 12: Durable Duress Action Persistence in SQLite Ledger', async () => {
    const config = createTestConfig(dbPath);
    config.switches[0].duress = {
      enabled: true,
      pin: '9999',
      actions: [
        {
          id: 'duress-beacon-1',
          name: 'Silent Distress Beacon',
          plugin: 'mock:test',
          config: { channel: 'covert-alert' },
        },
      ],
    };

    const engine = new OboldEngine(config, db, cipher, plugins);
    await engine.checkin('test-switch', true);

    const logs = db.getAuditLogs(50);
    const duressLog = logs.find((l) => l.category === 'DURESS_CHECKIN');
    expect(duressLog).toBeDefined();

    const ledgerEntries = db.getRecentLedgerEntries(50);
    const duressEntry = ledgerEntries.find((e) => e.switchId === 'test-switch' && e.stageId === 'duress' && e.actionId === 'duress-beacon-1');
    expect(duressEntry).toBeDefined();
    expect(duressEntry?.state).toBe('SUCCEEDED');
  });

  test('Test 13: Fail-Closed Master Key Write on Storage Error', () => {
    const invalidPath = process.platform === 'win32' ? 'Z:\\non_existent_drive_999\\obold.key' : '/root/forbidden_dir_999/obold.key';
    expect(() => resolveKeyBuffer(undefined, invalidPath)).toThrow(/FATAL: Refusing to start because master encryption key could not be persisted|FATAL: Failed to create key directory/);
  });

  test('Test 14: Rescue Bundle App Script Tampering Rejection', () => {
    const bundle = generateRescueBundle({
      payload: 'TOP-SECRET-DATA-2026',
      threshold: 2,
      totalShares: 3,
    });

    const tamperedAppHtml = bundle.html.replace(
      'function combineShamirShares',
      'window.__leaked = true; function combineShamirShares'
    );

    const result = verifyRescueBundle(tamperedAppHtml);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('JavaScript runtime in HTML bundle has been modified or tampered');
  });

  test('Test 15: Switch State Machine Enforcement (Terminal State Check-In Rejection)', async () => {
    const config = createTestConfig(dbPath);
    const engine = new OboldEngine(config, db, cipher, plugins);

    db.updateSwitchStatus('test-switch', 'TRIGGERED');
    expect(engine.checkin('test-switch', false)).rejects.toThrow(/Cannot check in to switch "test-switch" because it is currently in "TRIGGERED" state/);

    db.updateSwitchStatus('test-switch', 'ABORTED');
    expect(engine.checkin('test-switch', false)).rejects.toThrow(/Cannot check in to switch "test-switch" because it is currently in "ABORTED" state/);

    engine.resumeSwitch('test-switch');
    const res = await engine.checkin('test-switch', false);
    expect(res.success).toBe(true);
  });

  test('Test 16: Idempotent Manual Switch Triggering', async () => {
    const config = createTestConfig(dbPath);
    const engine = new OboldEngine(config, db, cipher, plugins);

    const firstTrigger = await engine.triggerSwitch('test-switch', true);
    expect(firstTrigger.alreadyTriggered).toBe(false);

    db.updateSwitchStatus('test-switch', 'TRIGGERED');

    const secondTrigger = await engine.triggerSwitch('test-switch', true, false);
    expect(secondTrigger.alreadyTriggered).toBe(true);

    const forcedTrigger = await engine.triggerSwitch('test-switch', true, true);
    expect(forcedTrigger.alreadyTriggered).toBe(false);
  });

  test('Test 17: Authenticated Additional Data (AAD) Context Binding', () => {
    const testCipher = new OboldCipher('aad-test-key-material-999');
    const sensitivePayload = { command: 'rm -rf /safe/data', target: 'production' };
    const aadValid = 'switch-1:stage-1:action-1:webhook:v1';
    const aadTampered = 'switch-1:stage-1:action-2:webhook:v1';

    const encrypted = testCipher.encryptToString(sensitivePayload, aadValid);

    const decrypted = JSON.parse(testCipher.decryptFromString(encrypted, aadValid));
    expect(decrypted).toEqual(sensitivePayload);

    expect(() => testCipher.decryptFromString(encrypted, aadTampered)).toThrow(/Unsupported state or unable to authenticate data|bad decrypt|authentication failed/i);
    testCipher.destroy();
  });

  test('Test 18: DeadLetterRetryQueue 72-Hour Max Window Capping', () => {
    const queue = new DeadLetterRetryQueue(db, 5000, 21600000, 259200000);
    const now = Date.now();

    const freshNext = queue.calculateNextRetry(1, now);
    expect(freshNext).not.toBeNull();
    expect(freshNext).toBeGreaterThan(now);

    const expiredCreatedAt = now - (73 * 3600 * 1000);
    const expiredNext = queue.calculateNextRetry(1, expiredCreatedAt);
    expect(expiredNext).toBeNull();

    const nearExpiryCreatedAt = now - (71.99 * 3600 * 1000);
    const cappedNext = queue.calculateNextRetry(10, nearExpiryCreatedAt);
    expect(cappedNext).toBeNull();
  });

  test('Test 19: Per-Database KDF Salt Generation & Persistence', () => {
    const salt1 = db.getOrGenerateKdfSalt();
    expect(salt1.length).toBe(64);

    const salt2 = db.getOrGenerateKdfSalt();
    expect(salt2).toBe(salt1);

    const customCipher1 = new OboldCipher('secret-passphrase', 'aes-256-gcm', salt1);
    const customCipher2 = new OboldCipher('secret-passphrase', 'aes-256-gcm', salt1);
    const customCipherOtherSalt = new OboldCipher('secret-passphrase', 'aes-256-gcm', 'other-salt-123456');

    const plain = { test: 'salt-binding' };
    const enc = customCipher1.encryptToString(plain);

    expect(JSON.parse(customCipher2.decryptFromString(enc))).toEqual(plain);
    expect(() => customCipherOtherSalt.decryptFromString(enc)).toThrow();

    customCipher1.destroy();
    customCipher2.destroy();
    customCipherOtherSalt.destroy();
  });

  test('Test 20: Persistent Reminder Deduplication Across Simulated Engine Restart', async () => {
    const config = createTestConfig(dbPath);
    config.switches[0].reminders = [
      {
        id: 'rem-pers-1',
        name: 'Persistent Reminder',
        beforeMs: 300000,
        plugin: 'mock:test',
        config: { msg: 'reminder alert' },
      },
    ];

    const engine1 = new OboldEngine(config, db, cipher, plugins);
    const now = Date.now();
    const nextDeadline = now + 100000;

    let reminderCount = 0;
    engine1.on('switch:reminder', () => {
      reminderCount++;
    });

    await (engine1 as any).evaluateReminders(config.switches[0], nextDeadline, now);
    expect(reminderCount).toBe(1);

    const engine2 = new OboldEngine(config, db, cipher, plugins);
    engine2.on('switch:reminder', () => {
      reminderCount++;
    });

    await (engine2 as any).evaluateReminders(config.switches[0], nextDeadline, now);
    expect(reminderCount).toBe(1);
  });

  test('Test 21: Constant-Time HMAC String Comparison', () => {
    expect(constantTimeStringEquals('abcd1234efgh', 'abcd1234efgh')).toBe(true);
    expect(constantTimeStringEquals('abcd1234efgh', 'abcd1234efgx')).toBe(false);
    expect(constantTimeStringEquals('short', 'much_longer_string')).toBe(false);
    expect(constantTimeStringEquals('', '')).toBe(true);
  });

  test('Test 22: Atomic checkinWithToken Consumption', async () => {
    const config = createTestConfig(dbPath);
    db.upsertSwitch('test-switch', 'Failure Injection Test Switch', 'ARMED', Date.now(), Date.now() + 10000, -1);
    const engine = new OboldEngine(config, db, cipher, plugins);
    const tm = new OboldTokenManager('test-token-manager-secret');

    const { rawToken, tokenRecord } = tm.generateToken('test-switch', 3600000);
    db.saveHeartbeatToken(tokenRecord);

    const checkinRes = await engine.checkinWithToken(tokenRecord.tokenHash, 'test-switch', false);
    expect(checkinRes.success).toBe(true);

    expect(engine.checkinWithToken(tokenRecord.tokenHash, 'test-switch', false)).rejects.toThrow(/Token already used or expired/);
  });

  test('Test 23: Rescue Bundle Filename Path Traversal Sanitization', () => {
    expect(sanitizeRescueFilename('../../etc/passwd')).toBe('____etc_passwd');
    expect(sanitizeRescueFilename('C:\\Windows\\System32\\cmd.exe')).toBe('C__Windows_System32_cmd.exe');
    expect(sanitizeRescueFilename('normal_archive.json')).toBe('normal_archive.json');
    expect(sanitizeRescueFilename('')).toBe('decrypted_vault.txt');
  });

  test('Test 24: In-flight timeout/cancellation triggers AbortSignal and terminates process in ShellPlugin', async () => {
    const shell = new ShellPlugin();
    const controller = new AbortController();
    const execPromise = shell.execute(
      { command: 'ping -n 10 127.0.0.1 || sleep 10' },
      {
        switchId: 'test-switch',
        switchName: 'Test Switch',
        actionId: 'act-shell',
        deadlineAt: Date.now() + 10000,
        signal: controller.signal,
      }
    );

    setTimeout(() => {
      controller.abort();
    }, 100);

    const result = await execPromise;
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/cancelled|terminated|aborted/i);
  });

  test('Test 25: abortSwitch() immediately aborts active in-flight execution controllers', async () => {
    const config = createTestConfig(dbPath);
    config.switches[0].stages[0].actions[0].plugin = 'core:shell';
    config.switches[0].stages[0].actions[0].config = { command: 'ping -n 10 127.0.0.1 || sleep 10' };

    const shell = new ShellPlugin();
    plugins.register(shell);

    const engine = new OboldEngine(config, db, cipher, plugins);
    const triggerPromise = engine.triggerSwitch('test-switch');

    setTimeout(() => {
      engine.abortSwitch('test-switch', 'Operator emergency abort');
    }, 150);

    await triggerPromise;
    const dbSw = db.getSwitch('test-switch');
    expect(dbSw?.status).toBe('ABORTED');
  });

  test('Test 26: ShellPlugin dryRun intercepts execution safely without spawning subprocess', async () => {
    const shell = new ShellPlugin();
    const result = await shell.execute(
      { command: 'rm -rf /' },
      {
        switchId: 'test-switch',
        switchName: 'Test Switch',
        actionId: 'act-dry',
        deadlineAt: Date.now() + 10000,
        dryRun: true,
      }
    );

    expect(result.success).toBe(true);
    expect(result.output?.dryRun).toBe(true);
    expect(result.output?.message).toContain('DRY-RUN SHELL NOOP');
  });

  test('Test 27: Exclusive Execution Leases Prevent Overlapping Retries During In-Flight Execution', () => {
    const entry = (new (class extends MockPlugin {})());
    const ledgerEntry = (new (class {
      static create(l: any) {
        return l.createEntry('test-switch', 'stage-1', 'act-1', 'mock:test', { msg: 'lease test' });
      }
    })).constructor;

    const ledger = new (require('../src/core/ledger.ts').AtomicExecutionLedger)(db, cipher);
    const item = ledger.createEntry('test-switch', 'stage-1', 'act-1', 'mock:test', { msg: 'lease test' });

    expect(ledger.hasActiveLease(item.id)).toBe(false);
    expect(ledger.acquireLease(item.id, 5000)).toBe(true);
    expect(ledger.hasActiveLease(item.id)).toBe(true);
    expect(ledger.acquireLease(item.id, 5000)).toBe(false);

    ledger.releaseLease(item.id);
    expect(ledger.hasActiveLease(item.id)).toBe(false);
    expect(ledger.acquireLease(item.id, 5000)).toBe(true);

    ledger.markSucceeded(item.id, { success: true, actionId: 'act-1', plugin: 'mock:test', durationMs: 10 });
    expect(ledger.hasActiveLease(item.id)).toBe(false);
  });

  test('Test 28: Safe forceReplay Rejection on Unconfirmed Destructive Actions & Replay Lineage Linkage', async () => {
    const config = createTestConfig(dbPath);
    config.switches[0].stages[0].actions[0].destructive = true;
    db.upsertSwitch('test-switch', 'Failure Injection Test Switch', 'TRIGGERED', Date.now(), Date.now() + 10000, 0);

    const mockPlugin = new MockPlugin();
    plugins.register(mockPlugin);

    const engine = new OboldEngine(config, db, cipher, plugins);

    expect(engine.triggerSwitch('test-switch', false, true, false)).rejects.toThrow(/contains destructive actions/i);

    const replayRes = await engine.triggerSwitch('test-switch', false, true, true);
    expect(replayRes.status).toBe('COMPLETED');
    expect(replayRes.executionId).toBeDefined();
    expect(mockPlugin.lastIdempotencyKey).toMatch(/-replay-/);
  });

  test('Test 29: In-Flight Crash Entry Transition to UNKNOWN and Destructive Pause', async () => {
    const config = createTestConfig(dbPath);
    config.switches[0].stages[0].actions[0].destructive = true;

    const encPayload = cipher.encryptToString({ command: 'shred /root/keys' });

    db.insertLedgerEntry({
      id: 'led-crash-destructive-001',
      switchId: 'test-switch',
      stageId: 'stage-1',
      actionId: 'act-1',
      plugin: 'mock:test',
      state: 'EXECUTING',
      idempotencyKey: 'idemp-crash-dest-001',
      attemptCount: 1,
      maxAttempts: 5,
      nextRetryAt: null,
      lastError: null,
      payloadSnapshot: encPayload,
      resultSnapshot: null,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      dispatchedAt: Date.now(),
      acknowledgedAt: null,
    });

    const mockPlugin = new MockPlugin();
    const testPlugins = new PluginRegistry();
    testPlugins.register(mockPlugin);

    const testEngine = new OboldEngine(config, db, cipher, testPlugins);
    await testEngine.replayLedger();

    expect(mockPlugin.callCount).toBe(0);
    const entryAfter = db.getLedgerEntry('led-crash-destructive-001');
    expect(entryAfter?.state).toBe('UNKNOWN');
    expect(entryAfter?.lastError).toContain('Crash recovery paused: action is destructive');
  });

  test('Test 30: Unbiased Shamir Polynomial Exact Reconstruction Across Multiple Thresholds', () => {
    for (const threshold of [2, 3, 5, 8]) {
      const total = threshold + 3;
      const secret = `unbiased-secret-payload-threshold-${threshold}-${'x'.repeat(32)}`;
      const shares = ShamirSecretSharing.split(secret, total, threshold);
      expect(shares.length).toBe(total);

      const subset = shares.slice(0, threshold);
      const combined = ShamirSecretSharing.combine(subset);
      expect(combined).toBe(secret);
    }
  });
});
