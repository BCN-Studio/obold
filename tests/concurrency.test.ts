import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { OboldDatabase } from '../src/db/database.ts';
import { OboldEngine } from '../src/core/engine.ts';
import { OboldCipher } from '../src/crypto/cipher.ts';
import { PluginRegistry } from '../src/plugins/registry.ts';
import type { OboldConfig, ExecutionResult } from '../src/config/types.ts';
import type { PluginExecutionContext } from '../src/plugins/types.ts';
import { unlinkSync, existsSync } from 'node:fs';

const TEST_DB = './data/test_concurrency.db';

function cleanupDb() {
  try {
    if (existsSync(TEST_DB)) unlinkSync(TEST_DB);
    if (existsSync(`${TEST_DB}-wal`)) unlinkSync(`${TEST_DB}-wal`);
    if (existsSync(`${TEST_DB}-shm`)) unlinkSync(`${TEST_DB}-shm`);
  } catch {}
}

describe('Scheduler Concurrency & Worker Isolation', () => {
  let db: OboldDatabase | null = null;
  let engine: OboldEngine | null = null;
  let cipher: OboldCipher;
  let plugins: PluginRegistry;

  beforeEach(() => {
    cleanupDb();
    db = new OboldDatabase(TEST_DB, true);
    cipher = new OboldCipher('concurrency-secret-key-123456789', 'chacha20-poly1305');
    plugins = new PluginRegistry();
  });

  afterEach(() => {
    if (engine) engine.stop();
    if (db) db.close();
    cleanupDb();
  });

  it('Evaluates multiple switches concurrently so slow tasks do not block other switches', async () => {
    let switch1Started = false;
    let switch1Completed = false;
    let switch2Completed = false;

    plugins.register({
      id: 'mock:slow',
      name: 'Slow Mock Plugin',
      description: 'Slow mock',
      version: '1.0.0',
      validateConfig: () => ({ valid: true }),
      execute: async (config: Record<string, any>, context: PluginExecutionContext): Promise<ExecutionResult> => {
        switch1Started = true;
        await new Promise((r) => setTimeout(r, 200));
        switch1Completed = true;
        return { success: true, actionId: context.actionId, plugin: 'mock:slow', durationMs: 200 };
      },
    });

    plugins.register({
      id: 'mock:fast',
      name: 'Fast Mock Plugin',
      description: 'Fast mock',
      version: '1.0.0',
      validateConfig: () => ({ valid: true }),
      execute: async (config: Record<string, any>, context: PluginExecutionContext): Promise<ExecutionResult> => {
        switch2Completed = true;
        return { success: true, actionId: context.actionId, plugin: 'mock:fast', durationMs: 5 };
      },
    });

    const now = Date.now();
    const config: OboldConfig = {
      version: '1.0.0',
      storage: { path: TEST_DB, walMode: true, autoCheckpointIntervalMs: 60000 },
      crypto: { algorithm: 'chacha20-poly1305', keyDerivation: 'scrypt' },
      server: { enabled: false, host: '127.0.0.1', port: 8080 },
      switches: [
        {
          id: 'switch-slow',
          name: 'Slow Switch',
          enabled: true,
          intervalMs: 100,
          gracePeriodMs: 0,
          reminders: [],
          stages: [
            {
              id: 'stage-slow',
              name: 'Slow Stage',
              delayMs: 0,
              actions: [{ id: 'act-slow', name: 'Slow Action', plugin: 'mock:slow', config: {} }],
            },
          ],
        },
        {
          id: 'switch-fast',
          name: 'Fast Switch',
          enabled: true,
          intervalMs: 100,
          gracePeriodMs: 0,
          reminders: [],
          stages: [
            {
              id: 'stage-fast',
              name: 'Fast Stage',
              delayMs: 0,
              actions: [{ id: 'act-fast', name: 'Fast Action', plugin: 'mock:fast', config: {} }],
            },
          ],
        },
      ],
    };

    engine = new OboldEngine(config, db!, cipher, plugins);

    db!.upsertSwitch('switch-slow', 'Slow Switch', 'ARMED', now - 500, now - 200, -1);
    db!.upsertSwitch('switch-fast', 'Fast Switch', 'ARMED', now - 500, now - 200, -1);

    await (engine as any).tick();

    expect(switch1Started).toBe(true);
    expect(switch2Completed).toBe(true);
  });

  it('Atomically consumes token and updates switch deadline in single transaction', async () => {
    const config: OboldConfig = {
      version: '1.0.0',
      storage: { path: TEST_DB, walMode: true, autoCheckpointIntervalMs: 60000 },
      crypto: { algorithm: 'chacha20-poly1305', keyDerivation: 'scrypt' },
      server: { enabled: false, host: '127.0.0.1', port: 8080 },
      switches: [
        {
          id: 'switch-atomic',
          name: 'Atomic Switch',
          enabled: true,
          intervalMs: 10000,
          gracePeriodMs: 0,
          reminders: [],
          stages: [],
        },
      ],
    };

    engine = new OboldEngine(config, db!, cipher, plugins);
    const tokenHash = 'test-token-hash-atomic-001';
    db!.saveHeartbeatToken({
      id: 'tok-1',
      switchId: 'switch-atomic',
      tokenHash,
      expiresAt: Date.now() + 60000,
      isDuress: false,
      createdAt: Date.now(),
    });

    const res1 = await engine.checkinWithToken(tokenHash, 'switch-atomic', false);
    expect(res1.success).toBe(true);
    expect(res1.nextDeadlineAt).toBeGreaterThan(Date.now());

    await expect(engine.checkinWithToken(tokenHash, 'switch-atomic', false)).rejects.toThrow(
      /Token already used or expired/
    );

    const tokenInDb = db!.findTokenByHash(tokenHash);
    expect(tokenInDb?.usedAt).not.toBeNull();
  });

  it('Marks reminder as FAILED and allows retry queue processing on delivery failure', async () => {
    let reminderCallCount = 0;
    plugins.register({
      id: 'mock:failing_reminder',
      name: 'Failing Reminder Plugin',
      description: 'Failing reminder',
      version: '1.0.0',
      validateConfig: () => ({ valid: true }),
      execute: async (): Promise<ExecutionResult> => {
        reminderCallCount++;
        return { success: false, actionId: 'rem-1', plugin: 'mock:failing_reminder', durationMs: 5, error: 'Network timeout' };
      },
    });

    const now = Date.now();
    const nextDeadline = now + 10000;
    const config: OboldConfig = {
      version: '1.0.0',
      storage: { path: TEST_DB, walMode: true, autoCheckpointIntervalMs: 60000 },
      crypto: { algorithm: 'chacha20-poly1305', keyDerivation: 'scrypt' },
      server: { enabled: false, host: '127.0.0.1', port: 8080 },
      switches: [
        {
          id: 'switch-rem-fail',
          name: 'Reminder Fail Switch',
          enabled: true,
          intervalMs: 30000,
          gracePeriodMs: 0,
          reminders: [
            {
              id: 'rem-fail-1',
              name: 'Failing Reminder',
              beforeMs: 20000,
              plugin: 'mock:failing_reminder',
              config: {},
            },
          ],
          stages: [],
        },
      ],
    };

    engine = new OboldEngine(config, db!, cipher, plugins);
    db!.upsertSwitch('switch-rem-fail', 'Reminder Fail Switch', 'ARMED', now - 5000, nextDeadline, -1);

    await (engine as any).evaluateReminders(config.switches[0], nextDeadline, now);
    expect(reminderCallCount).toBe(1);

    const cycleKey = `reminder:switch-rem-fail:rem-fail-1:${nextDeadline}`;
    const metaStatus = db!.getMetadata(cycleKey);
    expect(metaStatus).toBe('FAILED');

    const ledgerEntries = db!.getRecentLedgerEntries(10);
    const failedEntry = ledgerEntries.find((e) => e.actionId === 'rem-fail-1');
    expect(failedEntry).toBeDefined();
    expect(failedEntry?.state).toBe('FAILED_RETRYABLE');
  });

  it('Enforces API role/capability separation across read, checkin, and operator tokens', async () => {
    const config: OboldConfig = {
      version: '1.0.0',
      storage: { path: TEST_DB, walMode: true, autoCheckpointIntervalMs: 60000 },
      crypto: { algorithm: 'chacha20-poly1305', keyDerivation: 'scrypt' },
      server: {
        enabled: true,
        host: '0.0.0.0',
        port: 8080,
        apiKeys: [
          { token: 'token-read-only', roles: ['read'] },
          { token: 'token-checkin-only', roles: ['checkin'] },
          { token: 'token-operator', roles: ['operator'] },
        ],
      },
      switches: [
        {
          id: 'switch-rbac',
          name: 'RBAC Switch',
          enabled: true,
          intervalMs: 30000,
          gracePeriodMs: 0,
          reminders: [],
          stages: [],
        },
      ],
    };

    engine = new OboldEngine(config, db!, cipher, plugins);
    db!.upsertSwitch('switch-rbac', 'RBAC Switch', 'ARMED', Date.now() - 5000, Date.now() + 30000, -1);

    const { ApiRouter } = require('../src/server/api.ts');
    const { OboldTokenManager } = require('../src/crypto/token.ts');
    const { SseEventBus } = require('../src/server/sse.ts');
    const { HealthHandler } = require('../src/server/health.ts');

    const router = new ApiRouter(
      engine,
      new OboldTokenManager('dummy-secret'),
      new SseEventBus(),
      new HealthHandler(engine),
      config.server
    );

    const readReq = new Request('http://0.0.0.0:8080/api/v1/switches', {
      method: 'GET',
      headers: { Authorization: 'Bearer token-read-only' },
    });
    const readRes = await router.handleRequest(readReq);
    expect(readRes.status).toBe(200);

    const forbiddenTriggerReq = new Request('http://0.0.0.0:8080/api/v1/switches/switch-rbac/trigger', {
      method: 'POST',
      headers: { Authorization: 'Bearer token-read-only' },
    });
    const forbiddenTriggerRes = await router.handleRequest(forbiddenTriggerReq);
    expect(forbiddenTriggerRes.status).toBe(403);

    const checkinReq = new Request('http://0.0.0.0:8080/api/v1/switches/switch-rbac/checkin', {
      method: 'POST',
      headers: { Authorization: 'Bearer token-checkin-only' },
    });
    const checkinRes = await router.handleRequest(checkinReq);
    expect(checkinRes.status).toBe(200);

    const forbiddenOperatorReq = new Request('http://0.0.0.0:8080/api/v1/switches/switch-rbac/trigger', {
      method: 'POST',
      headers: { Authorization: 'Bearer token-checkin-only' },
    });
    const forbiddenOperatorRes = await router.handleRequest(forbiddenOperatorReq);
    expect(forbiddenOperatorRes.status).toBe(403);

    const operatorTriggerReq = new Request('http://0.0.0.0:8080/api/v1/switches/switch-rbac/trigger', {
      method: 'POST',
      headers: { Authorization: 'Bearer token-operator' },
    });
    const operatorTriggerRes = await router.handleRequest(operatorTriggerReq);
    expect(operatorTriggerRes.status).toBe(200);

    router.destroy();
  });
});
