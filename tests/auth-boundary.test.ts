import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { normalizeAndValidateConfig, resolveEnvPlaceholders } from '../src/config/loader.ts';
import { OboldDatabase } from '../src/db/database.ts';
import { OboldEngine } from '../src/core/engine.ts';
import { OboldCipher } from '../src/crypto/cipher.ts';
import { PluginRegistry } from '../src/plugins/registry.ts';
import { OboldTokenManager } from '../src/crypto/token.ts';
import { HealthHandler } from '../src/server/health.ts';
import { SseEventBus } from '../src/server/sse.ts';
import { ApiRouter } from '../src/server/api.ts';
import { unlinkSync, existsSync } from 'node:fs';

const TEST_DB = './data/test_auth_boundary.db';

function cleanupDb() {
  try {
    if (existsSync(TEST_DB)) unlinkSync(TEST_DB);
    if (existsSync(`${TEST_DB}-wal`)) unlinkSync(`${TEST_DB}-wal`);
    if (existsSync(`${TEST_DB}-shm`)) unlinkSync(`${TEST_DB}-shm`);
  } catch {}
}

describe('Security Boundaries & Authentication Enforcement', () => {
  let db: OboldDatabase | null = null;
  let engine: OboldEngine | null = null;
  let tokenManager: OboldTokenManager;
  let sseBus: SseEventBus;
  let healthHandler: HealthHandler;
  let cipher: OboldCipher;
  let plugins: PluginRegistry;

  beforeEach(() => {
    cleanupDb();
    db = new OboldDatabase(TEST_DB, true);
    cipher = new OboldCipher('test_key_phase1_32bytes_long!', 'chacha20-poly1305');
    plugins = new PluginRegistry();

    const config = normalizeAndValidateConfig({
      version: '1.0.0',
      storage: { path: TEST_DB },
      crypto: { algorithm: 'chacha20-poly1305', keyDerivation: 'scrypt' },
      server: { enabled: true, host: '127.0.0.1', port: 8080, apiAuthToken: 'secret_token_123' },
      switches: [
        {
          id: 'test-switch',
          name: 'Test Switch',
          interval: '1h',
          gracePeriod: '10m',
          stages: [{ id: 's1', name: 'Stage 1', actions: [{ id: 'a1', plugin: 'core:webhook', config: {} }] }],
        },
      ],
    });

    engine = new OboldEngine(config, db, cipher, plugins);
    tokenManager = new OboldTokenManager('token_secret_phase1_key!');
    sseBus = new SseEventBus();
    healthHandler = new HealthHandler(engine);
  });

  afterEach(() => {
    if (db) {
      db.close();
      db = null;
    }
    cleanupDb();
  });

  it('Refuses remote host binding (0.0.0.0) without apiAuthToken', () => {
    expect(() => {
      normalizeAndValidateConfig({
        version: '1.0.0',
        server: { enabled: true, host: '0.0.0.0' },
        switches: [],
      });
    }).toThrow(/Refusing remote host binding/);
  });

  it('Refuses remote host binding with wildcard CORS (*)', () => {
    expect(() => {
      normalizeAndValidateConfig({
        version: '1.0.0',
        server: { enabled: true, host: '0.0.0.0', apiAuthToken: 'valid_token_123', corsOrigins: ['*'] },
        switches: [],
      });
    }).toThrow(/wildcard CORS origin/);
  });

  it('Fails immediately if a required environment variable is unset or empty', () => {
    expect(() => {
      resolveEnvPlaceholders({
        secretKey: '${REQUIRED:NON_EXISTENT_SECRET_2026}',
      }, {});
    }).toThrow(/Required environment variable "NON_EXISTENT_SECRET_2026" is missing or empty/);
  });

  it('Gates /metrics and /events behind authentication by default', async () => {
    if (!engine) throw new Error('Engine not initialized');
    const router = new ApiRouter(engine, tokenManager, sseBus, healthHandler, {
      host: '127.0.0.1',
      port: 8080,
      apiAuthToken: 'bearer_token_xyz',
      publicMetrics: false,
      publicEvents: false,
    });

    const unauthMetricsReq = new Request('http://127.0.0.1:8080/metrics', { method: 'GET' });
    const unauthMetricsRes = await router.handleRequest(unauthMetricsReq);
    expect(unauthMetricsRes.status).toBe(401);

    const authMetricsReq = new Request('http://127.0.0.1:8080/metrics', {
      method: 'GET',
      headers: { Authorization: 'Bearer bearer_token_xyz' },
    });
    const authMetricsRes = await router.handleRequest(authMetricsReq);
    expect(authMetricsRes.status).toBe(200);

    router.destroy();
  });

  it('Prevents GET checkin prefetching from consuming single-use tokens', async () => {
    if (!engine || !db) throw new Error('Engine or DB not initialized');
    const router = new ApiRouter(engine, tokenManager, sseBus, healthHandler, {
      host: '127.0.0.1',
      port: 8080,
    });

    const { rawToken, tokenRecord } = tokenManager.generateToken('test-switch', 60000);
    db.saveHeartbeatToken(tokenRecord);

    const getPrefetchReq = new Request(`http://127.0.0.1:8080/checkin?token=${rawToken}`, { method: 'GET' });
    const getPrefetchRes = await router.handleRequest(getPrefetchReq);
    expect(getPrefetchRes.status).toBe(200);
    const getHtml = await getPrefetchRes.text();
    expect(getHtml).toContain('Confirm Dead Man Switch Check-In');

    const tokenHash = tokenManager.hashToken(rawToken);
    const tokenInDbBefore = db.getSqlite().query('SELECT used_at FROM heartbeat_tokens WHERE token_hash = ?').get(tokenHash) as any;
    expect(tokenInDbBefore.used_at).toBeNull();

    const postConsumeReq = new Request('http://127.0.0.1:8080/checkin/consume', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ token: rawToken }),
    });
    const postConsumeRes = await router.handleRequest(postConsumeReq);
    expect(postConsumeRes.status).toBe(200);
    const postJson: any = await postConsumeRes.json();
    expect(postJson.success).toBe(true);
    expect(postJson.switchId).toBe('test-switch');

    const tokenInDbAfter = db.getSqlite().query('SELECT used_at FROM heartbeat_tokens WHERE token_hash = ?').get(tokenHash) as any;
    expect(tokenInDbAfter.used_at).not.toBeNull();

    const replayReq = new Request('http://127.0.0.1:8080/checkin/consume', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ token: rawToken }),
    });
    const replayRes = await router.handleRequest(replayReq);
    expect(replayRes.status).toBe(400);

    router.destroy();
  });

  it('Blocks remote Shamir secret split and combine unless explicitly enabled', async () => {
    if (!engine) throw new Error('Engine not initialized');
    const router = new ApiRouter(engine, tokenManager, sseBus, healthHandler, {
      host: '0.0.0.0',
      port: 8080,
      apiAuthToken: 'token_remote_abc',
      allowRemoteCryptoApi: false,
    });

    const remoteShamirReq = new Request('http://0.0.0.0:8080/api/v1/crypto/shamir/split', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer token_remote_abc',
        'Content-Type': 'application/json',
        'X-Real-IP': '198.51.100.42',
      },
      body: JSON.stringify({ secret: 'super_secret_payload', total: 5, threshold: 3 }),
    });

    const remoteShamirRes = await router.handleRequest(remoteShamirReq);
    expect(remoteShamirRes.status).toBe(403);
    const errJson: any = await remoteShamirRes.json();
    expect(errJson.error).toContain('Remote Shamir secret reconstruction over HTTP API is permanently disabled');

    router.destroy();
  });
});
