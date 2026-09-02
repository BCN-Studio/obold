import { timingSafeEqual, createHash } from 'node:crypto';
import type { OboldEngine } from '../core/engine.ts';
import type { OboldTokenManager } from '../crypto/token.ts';
import { ShamirSecretSharing } from '../crypto/shamir.ts';
import type { SseEventBus } from './sse.ts';
import type { HealthHandler } from './health.ts';
import { InMemoryRateLimiter, type RateLimitResult } from './rate-limiter.ts';
import type { ServerConfig } from '../config/types.ts';

export class ApiRouter {
  private engine: OboldEngine;
  private tokenManager: OboldTokenManager;
  private sseBus: SseEventBus;
  private healthHandler: HealthHandler;
  private serverConfig: ServerConfig;
  private allowedOrigins: Set<string>;
  private allowAnyOrigin: boolean;
  private rateLimiter: InMemoryRateLimiter;

  constructor(
    engine: OboldEngine,
    tokenManager: OboldTokenManager,
    sseBus: SseEventBus,
    healthHandler: HealthHandler,
    serverConfig?: Partial<ServerConfig>
  ) {
    this.engine = engine;
    this.tokenManager = tokenManager;
    this.sseBus = sseBus;
    this.healthHandler = healthHandler;

    const host = serverConfig?.host || '127.0.0.1';
    const port = serverConfig?.port || 8080;

    this.serverConfig = {
      enabled: serverConfig?.enabled !== false,
      host,
      port,
      apiAuthToken: serverConfig?.apiAuthToken,
      apiKeys: serverConfig?.apiKeys,
      corsOrigins: serverConfig?.corsOrigins,
      trustedProxies: serverConfig?.trustedProxies,
      allowRemoteCryptoApi: serverConfig?.allowRemoteCryptoApi === true,
      publicHealth: serverConfig?.publicHealth !== false,
      publicCheckin: serverConfig?.publicCheckin !== false,
      publicMetrics: serverConfig?.publicMetrics === true,
      publicEvents: serverConfig?.publicEvents === true,
    };

    this.rateLimiter = new InMemoryRateLimiter(60000, this.serverConfig.trustedProxies);

    const defaultOrigins = [
      `http://127.0.0.1:${port}`,
      `http://localhost:${port}`,
      `http://${host}:${port}`,
      `https://127.0.0.1:${port}`,
      `https://localhost:${port}`,
      `https://${host}:${port}`,
    ];

    const configured = this.serverConfig.corsOrigins && this.serverConfig.corsOrigins.length > 0
      ? this.serverConfig.corsOrigins
      : defaultOrigins;

    this.allowAnyOrigin = configured.includes('*');
    this.allowedOrigins = new Set(configured.map((o) => o.trim().toLowerCase()));

    this.engine.on('switch:checkin', (data) => this.sseBus.broadcast('switch:checkin', data));
    this.engine.on('switch:triggered', (data) => this.sseBus.broadcast('switch:triggered', data));
    this.engine.on('switch:duress', (data) => this.sseBus.broadcast('switch:duress', data));
    this.engine.on('tick', (data) => this.sseBus.broadcast('tick', { states: this.engine.getRuntimeStates(), ...data }));
  }

  public destroy(): void {
    this.rateLimiter.destroy();
  }

  private safeCompare(a?: string, b?: string): boolean {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const bufA = Buffer.from(a, 'utf-8');
    const bufB = Buffer.from(b, 'utf-8');
    if (bufA.length === 0 || bufB.length === 0) return false;
    const hashA = createHash('sha256').update(bufA).digest();
    const hashB = createHash('sha256').update(bufB).digest();
    return timingSafeEqual(hashA, hashB);
  }

  private getCallerRoles(req: Request): Set<string> {
    const authHeader = req.headers.get('Authorization');
    const tokenHeader = req.headers.get('X-Obold-Token');
    let token = '';
    if (authHeader) {
      token = authHeader.replace(/^Bearer\s+/i, '').trim();
    } else if (tokenHeader) {
      token = tokenHeader.trim();
    }

    const isLoopback = this.serverConfig.host === '127.0.0.1' || this.serverConfig.host === 'localhost' || this.serverConfig.host === '::1';
    const hasConfiguredTokens = Boolean(
      this.serverConfig.apiAuthToken ||
      (this.serverConfig.apiKeys && this.serverConfig.apiKeys.length > 0) ||
      process.env.OBOLD_API_ADMIN_TOKEN ||
      process.env.OBOLD_API_OPERATOR_TOKEN ||
      process.env.OBOLD_API_CHECKIN_TOKEN ||
      process.env.OBOLD_API_READ_TOKEN
    );

    if (!token) {
      if (!hasConfiguredTokens && isLoopback) {
        return new Set(['admin', 'operator', 'checkin', 'read']);
      }
      return new Set();
    }

    const roles = new Set<string>();

    if (this.serverConfig.apiAuthToken && this.safeCompare(token, this.serverConfig.apiAuthToken)) {
      roles.add('admin');
      roles.add('operator');
      roles.add('checkin');
      roles.add('read');
    }

    if (this.serverConfig.apiKeys && this.serverConfig.apiKeys.length > 0) {
      for (const key of this.serverConfig.apiKeys) {
        if (this.safeCompare(token, key.token)) {
          for (const r of key.roles) {
            if (r === 'admin') {
              roles.add('admin');
              roles.add('operator');
              roles.add('checkin');
              roles.add('read');
            } else if (r === 'operator') {
              roles.add('operator');
              roles.add('checkin');
              roles.add('read');
            } else if (r === 'checkin') {
              roles.add('checkin');
            } else if (r === 'read') {
              roles.add('read');
            }
          }
        }
      }
    }

    if (process.env.OBOLD_API_ADMIN_TOKEN && this.safeCompare(token, process.env.OBOLD_API_ADMIN_TOKEN)) {
      roles.add('admin');
      roles.add('operator');
      roles.add('checkin');
      roles.add('read');
    }
    if (process.env.OBOLD_API_OPERATOR_TOKEN && this.safeCompare(token, process.env.OBOLD_API_OPERATOR_TOKEN)) {
      roles.add('operator');
      roles.add('checkin');
      roles.add('read');
    }
    if (process.env.OBOLD_API_CHECKIN_TOKEN && this.safeCompare(token, process.env.OBOLD_API_CHECKIN_TOKEN)) {
      roles.add('checkin');
    }
    if (process.env.OBOLD_API_READ_TOKEN && this.safeCompare(token, process.env.OBOLD_API_READ_TOKEN)) {
      roles.add('read');
    }

    return roles;
  }

  private isAuthorized(req: Request, requiredRole: string = 'read'): { authorized: boolean; authenticated: boolean } {
    const roles = this.getCallerRoles(req);
    if (roles.size === 0) {
      return { authorized: false, authenticated: false };
    }
    const authorized = roles.has(requiredRole) || roles.has('admin');
    return { authorized, authenticated: true };
  }

  public getCorsHeaders(req: Request): Record<string, string> {
    const origin = req.headers.get('Origin');
    if (!origin) {
      return {};
    }

    const normOrigin = origin.trim().toLowerCase();
    if (this.allowAnyOrigin) {
      return {
        'Access-Control-Allow-Origin': '*',
        'Vary': 'Origin',
      };
    }

    if (this.allowedOrigins.has(normOrigin)) {
      return {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Credentials': 'true',
        'Vary': 'Origin',
      };
    }

    return {};
  }

  private rateLimitResponse(rateLimitResult: RateLimitResult, limit: number, req: Request): Response {
    const corsHeaders = this.getCorsHeaders(req);
    return new Response(
      JSON.stringify({
        error: 'Too many requests. Please slow down and try again later.',
        retryAfter: rateLimitResult.retryAfterSec,
      }),
      {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': rateLimitResult.retryAfterSec.toString(),
          'RateLimit-Limit': limit.toString(),
          'RateLimit-Remaining': '0',
          'RateLimit-Reset': Math.ceil(rateLimitResult.resetAt / 1000).toString(),
          ...corsHeaders,
        },
      }
    );
  }

  public async handleRequest(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method.toUpperCase();
    const clientIp = this.rateLimiter.getClientIp(req);

    if (method === 'OPTIONS') {
      const origin = req.headers.get('Origin');
      if (!origin) {
        return new Response(null, { status: 204 });
      }

      const normOrigin = origin.trim().toLowerCase();
      if (this.allowAnyOrigin) {
        return new Response(null, {
          status: 204,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Obold-Token',
            'Access-Control-Max-Age': '86400',
            'Vary': 'Origin',
          },
        });
      }

      if (this.allowedOrigins.has(normOrigin)) {
        return new Response(null, {
          status: 204,
          headers: {
            'Access-Control-Allow-Origin': origin,
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Obold-Token',
            'Access-Control-Max-Age': '86400',
            'Vary': 'Origin',
          },
        });
      }

      return new Response(JSON.stringify({ error: 'Forbidden: origin not allowed by CORS policy' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (path === '/healthz') {
      if (this.serverConfig.publicHealth === false) {
        const auth = this.isAuthorized(req, 'read');
        if (!auth.authenticated) return this.jsonResponse({ error: 'Unauthorized: health endpoint requires authentication' }, 401, req);
        if (!auth.authorized) return this.jsonResponse({ error: 'Forbidden: Insufficient token permissions. Required: "read"' }, 403, req);
      }
      return this.healthHandler.getHealthz();
    }

    if (path === '/readyz') {
      if (this.serverConfig.publicHealth === false) {
        const auth = this.isAuthorized(req, 'read');
        if (!auth.authenticated) return this.jsonResponse({ error: 'Unauthorized: readyz endpoint requires authentication' }, 401, req);
        if (!auth.authorized) return this.jsonResponse({ error: 'Forbidden: Insufficient token permissions. Required: "read"' }, 403, req);
      }
      return this.healthHandler.getReadyz();
    }

    if (path === '/metrics') {
      const isLoopbackIp = clientIp === '127.0.0.1' || clientIp === '::1' || clientIp === 'localhost';
      if ((!isLoopbackIp || this.serverConfig.publicMetrics !== true) && this.serverConfig.publicMetrics !== true) {
        const auth = this.isAuthorized(req, 'read');
        if (!auth.authenticated) {
          return this.jsonResponse({ error: 'Unauthorized: metrics endpoint requires authentication' }, 401, req);
        }
        if (!auth.authorized) {
          return this.jsonResponse({ error: 'Forbidden: Insufficient token permissions. Required: "read"' }, 403, req);
        }
      }
      return this.healthHandler.getPrometheusMetrics();
    }

    if (path === '/events' || path === '/api/v1/events') {
      const isLoopbackIp = clientIp === '127.0.0.1' || clientIp === '::1' || clientIp === 'localhost';
      if ((!isLoopbackIp || this.serverConfig.publicEvents !== true) && this.serverConfig.publicEvents !== true) {
        const auth = this.isAuthorized(req, 'read');
        if (!auth.authenticated) {
          return this.jsonResponse({ error: 'Unauthorized: events stream requires authentication' }, 401, req);
        }
        if (!auth.authorized) {
          return this.jsonResponse({ error: 'Forbidden: Insufficient token permissions. Required: "read"' }, 403, req);
        }
      }
      return this.sseBus.handleConnection(this.getCorsHeaders(req));
    }

    if (path === '/checkin' && method === 'GET') {
      const checkinRl = this.rateLimiter.consume(`checkin-view:${clientIp}`, 20, 60000);
      if (!checkinRl.allowed) {
        return this.rateLimitResponse(checkinRl, 20, req);
      }
      return this.renderCheckinConfirmation(url);
    }

    if ((path === '/checkin/consume' || path === '/checkin') && method === 'POST') {
      const checkinRl = this.rateLimiter.consume(`checkin-consume:${clientIp}`, 10, 60000);
      if (!checkinRl.allowed) {
        return this.rateLimitResponse(checkinRl, 10, req);
      }
      return this.consumeCheckinToken(req, url);
    }

    if (path.startsWith('/api/v1/')) {
      const globalRl = this.rateLimiter.consume(`api-global:${clientIp}`, 120, 60000);
      if (!globalRl.allowed) {
        return this.rateLimitResponse(globalRl, 120, req);
      }

      let requiredRole = 'read';
      if (path.endsWith('/trigger') || path.endsWith('/abort') || path === '/api/v1/token/generate') {
        requiredRole = 'operator';
      } else if (path.endsWith('/checkin') || path.endsWith('/duress')) {
        requiredRole = 'checkin';
      }

      const isLoopback = this.serverConfig.host === '127.0.0.1' || this.serverConfig.host === 'localhost' || this.serverConfig.host === '::1';
      const hasConfiguredTokens = Boolean(
        this.serverConfig.apiAuthToken ||
        (this.serverConfig.apiKeys && this.serverConfig.apiKeys.length > 0) ||
        process.env.OBOLD_API_ADMIN_TOKEN ||
        process.env.OBOLD_API_OPERATOR_TOKEN ||
        process.env.OBOLD_API_CHECKIN_TOKEN ||
        process.env.OBOLD_API_READ_TOKEN
      );

      if (hasConfiguredTokens || !isLoopback) {
        const auth = this.isAuthorized(req, requiredRole);
        if (!auth.authenticated) {
          const authFailRl = this.rateLimiter.consume(`auth-fail:${clientIp}`, 5, 60000);
          if (!authFailRl.allowed) {
            return this.rateLimitResponse(authFailRl, 5, req);
          }
          return this.jsonResponse({ error: 'Unauthorized: invalid or missing API token' }, 401, req);
        }
        if (!auth.authorized) {
          return this.jsonResponse({ error: `Forbidden: Insufficient token permissions. Required role: "${requiredRole}"` }, 403, req);
        }
      }
    }

    if (path === '/api/v1/switches' && method === 'GET') {
      return this.jsonResponse({ switches: this.engine.getRuntimeStates() }, 200, req);
    }

    const checkinMatch = path.match(/^\/api\/v1\/switches\/([a-zA-Z0-9_-]+)\/checkin$/);
    if (checkinMatch && method === 'POST') {
      const switchId = checkinMatch[1];
      const swCheckinRl = this.rateLimiter.consume(`sw-checkin:${clientIp}:${switchId}`, 20, 60000);
      if (!swCheckinRl.allowed) {
        return this.rateLimitResponse(swCheckinRl, 20, req);
      }

      try {
        const result = await this.engine.checkin(switchId, false);
        return this.jsonResponse({ switchId, ...result }, 200, req);
      } catch (err: any) {
        return this.jsonResponse({ error: err.message }, 404, req);
      }
    }

    const duressMatch = path.match(/^\/api\/v1\/switches\/([a-zA-Z0-9_-]+)\/duress$/);
    if (duressMatch && method === 'POST') {
      const switchId = duressMatch[1];
      const duressRl = this.rateLimiter.consume(`sw-duress:${clientIp}:${switchId}`, 5, 60000);
      if (!duressRl.allowed) {
        return this.rateLimitResponse(duressRl, 5, req);
      }

      try {
        const result = await this.engine.checkin(switchId, true);
        return this.jsonResponse({ switchId, ...result }, 200, req);
      } catch (err: any) {
        return this.jsonResponse({ error: err.message }, 404, req);
      }
    }

    const triggerMatch = path.match(/^\/api\/v1\/switches\/([a-zA-Z0-9_-]+)\/trigger$/);
    if (triggerMatch && method === 'POST') {
      const switchId = triggerMatch[1];
      const triggerRl = this.rateLimiter.consume(`sw-trigger:${clientIp}:${switchId}`, 5, 60000);
      if (!triggerRl.allowed) {
        return this.rateLimitResponse(triggerRl, 5, req);
      }

      let body: any = {};
      try {
        body = await req.json();
      } catch {}

      const dryRun = url.searchParams.get('dryRun') === 'true' || body.dryRun === true;
      const forceReplay = url.searchParams.get('forceReplay') === 'true' || body.forceReplay === true;
      const confirmDestructive = url.searchParams.get('confirmDestructive') === 'true' || body.confirmDestructive === true;

      try {
        const res = await this.engine.triggerSwitch(switchId, dryRun, forceReplay, confirmDestructive);
        return this.jsonResponse({
          success: true,
          switchId,
          executionId: res.executionId,
          triggeredAt: res.triggeredAt,
          dryRun,
          forceReplay,
          alreadyTriggered: res.alreadyTriggered,
          status: res.status,
          results: res.results || [],
          message: `Switch ${switchId} triggered successfully.`,
        }, 200, req);
      } catch (err: any) {
        return this.jsonResponse({ error: err.message }, 400, req);
      }
    }

    const abortMatch = path.match(/^\/api\/v1\/switches\/([a-zA-Z0-9_-]+)\/abort$/);
    if (abortMatch && method === 'POST') {
      const switchId = abortMatch[1];
      const abortRl = this.rateLimiter.consume(`sw-abort:${clientIp}:${switchId}`, 5, 60000);
      if (!abortRl.allowed) {
        return this.rateLimitResponse(abortRl, 5, req);
      }

      let reason = 'API remote abort';
      try {
        const body: any = await req.json();
        if (body && body.reason) reason = body.reason;
      } catch {}

      const ok = this.engine.abortSwitch(switchId, reason);
      if (ok) {
        return this.jsonResponse({ success: true, switchId, status: 'ABORTED', message: `Switch ${switchId} cascade aborted.` }, 200, req);
      } else {
        return this.jsonResponse({ error: `Switch not found: ${switchId}` }, 404, req);
      }
    }

    if (path === '/api/v1/ledger' && method === 'GET') {
      const limit = parseInt(url.searchParams.get('limit') || '50', 10);
      const entries = this.engine.getDb().getRecentLedgerEntries(limit);
      return this.jsonResponse({ entries }, 200, req);
    }

    if (path === '/api/v1/audit' && method === 'GET') {
      const limit = parseInt(url.searchParams.get('limit') || '100', 10);
      const switchId = url.searchParams.get('switchId') || undefined;
      const logs = this.engine.getDb().getAuditLogs(limit, switchId);
      return this.jsonResponse({ logs }, 200, req);
    }

    if (path === '/api/v1/token/generate' && method === 'POST') {
      const tokenGenRl = this.rateLimiter.consume(`token-gen:${clientIp}`, 10, 60000);
      if (!tokenGenRl.allowed) {
        return this.rateLimitResponse(tokenGenRl, 10, req);
      }

      try {
        const body: any = await req.json();
        const switchId = body.switchId;
        const ttlMs = body.ttlMs || 86400000;
        const isDuress = body.isDuress === true;

        if (!switchId) return this.jsonResponse({ error: 'Missing required field: "switchId"' }, 400, req);

        const { rawToken, tokenRecord } = this.tokenManager.generateToken(switchId, ttlMs, isDuress);
        this.engine.getDb().saveHeartbeatToken(tokenRecord);

        return this.jsonResponse({
          success: true,
          switchId,
          token: rawToken,
          expiresAt: tokenRecord.expiresAt,
          checkinUrl: `${url.origin}/checkin?token=${rawToken}`,
        }, 200, req);
      } catch (err: any) {
        return this.jsonResponse({ error: err.message }, 400, req);
      }
    }

    if (path === '/api/v1/crypto/shamir/combine' || path === '/api/v1/crypto/shamir/split') {
      return this.jsonResponse({
        error: 'Forbidden: Remote Shamir secret reconstruction over HTTP API is permanently disabled for security. Use local CLI command "obold secret combine" or "obold secret split".'
      }, 403, req);
    }

    return this.jsonResponse({ error: `Route not found: ${method} ${path}` }, 404, req);
  }

  private escapeHtml(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  private renderCheckinConfirmation(url: URL): Response {
    const rawToken = url.searchParams.get('token');

    const baseHeaders = {
      'Content-Type': 'text/html; charset=utf-8',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'Pragma': 'no-cache',
    };

    if (!rawToken) {
      return new Response('<h3>Missing check-in token.</h3>', {
        status: 400,
        headers: baseHeaders,
      });
    }

    const verification = this.tokenManager.parseAndVerifyToken(rawToken);
    if (!verification.valid || !verification.switchId) {
      return new Response(
        `<!DOCTYPE html><html><body style="background:#0a0c10;color:#f87171;font-family:sans-serif;text-align:center;padding:50px;">
          <h2>❌ Check-In Verification Failed</h2>
          <p>${this.escapeHtml(verification.error || 'Invalid or expired token.')}</p>
        </body></html>`,
        { status: 400, headers: baseHeaders }
      );
    }

    return new Response(
      `<!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>obold — Confirm Check-in</title>
        <style>
          body { background: #07090e; color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
          .card { background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 40px; text-align: center; max-width: 480px; box-shadow: 0 20px 40px rgba(0,0,0,0.5); }
          .badge { display: inline-block; background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 9999px; padding: 6px 16px; font-size: 13px; font-weight: 600; margin-bottom: 20px; }
          h1 { margin: 0 0 12px 0; font-size: 24px; font-weight: 700; }
          p { color: #9ca3af; margin: 0 0 24px 0; font-size: 15px; line-height: 1.5; }
          .btn { display: block; width: 100%; padding: 14px 20px; background: #ffffff; color: #000000; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; text-decoration: none; box-sizing: border-box; }
          .btn:hover { background: #e5e7eb; }
          .footer { font-size: 12px; color: #6b7280; margin-top: 24px; }
        </style>
      </head>
      <body>
        <div class="card">
          <div class="badge">SINGLE-USE HEARTBEAT LINK</div>
          <h1>Confirm Dead Man Switch Check-In</h1>
          <p>Target Switch: <strong>${this.escapeHtml(verification.switchId)}</strong></p>
          <form method="POST" action="/checkin/consume">
            <input type="hidden" name="token" value="${this.escapeHtml(rawToken)}">
            <button type="submit" class="btn">Tap to Confirm Check-In</button>
          </form>
          <div class="footer">Protected against bot prefetching • obold Sovereign Daemon</div>
        </div>
      </body>
      </html>`,
      { status: 200, headers: baseHeaders }
    );
  }

  private async consumeCheckinToken(req: Request, url: URL): Promise<Response> {
    const baseHeaders = {
      'Content-Type': 'text/html; charset=utf-8',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'Pragma': 'no-cache',
    };

    let rawToken: string | null = url.searchParams.get('token');

    const contentType = req.headers.get('content-type') || '';
    if (!rawToken && contentType.includes('application/json')) {
      try {
        const body: any = await req.json();
        rawToken = body.token || null;
      } catch {}
    } else if (!rawToken && contentType.includes('application/x-www-form-urlencoded')) {
      try {
        const formText = await req.text();
        const formParams = new URLSearchParams(formText);
        rawToken = formParams.get('token');
      } catch {}
    }

    const isJsonAccept = (req.headers.get('accept') || '').includes('application/json');

    if (!rawToken) {
      if (isJsonAccept) {
        return this.jsonResponse({ error: 'Missing check-in token' }, 400, req);
      }
      return new Response('<h3>Missing check-in token.</h3>', { status: 400, headers: baseHeaders });
    }

    const verification = this.tokenManager.parseAndVerifyToken(rawToken);
    if (!verification.valid || !verification.switchId) {
      if (isJsonAccept) {
        return this.jsonResponse({ error: verification.error || 'Invalid or expired token' }, 400, req);
      }
      return new Response(
        `<!DOCTYPE html><html><body style="background:#0a0c10;color:#f87171;font-family:sans-serif;text-align:center;padding:50px;">
          <h2>❌ Check-In Verification Failed</h2>
          <p>${this.escapeHtml(verification.error || 'Invalid or expired token.')}</p>
        </body></html>`,
        { status: 400, headers: baseHeaders }
      );
    }

    const tokenHash = this.tokenManager.hashToken(rawToken);

    try {
      const checkinResult = await this.engine.checkinWithToken(tokenHash, verification.switchId, verification.isDuress);
      const deadlineStr = new Date(checkinResult.nextDeadlineAt).toLocaleString();

      if (isJsonAccept) {
        return this.jsonResponse({
          success: true,
          switchId: verification.switchId,
          isDuress: verification.isDuress,
          nextDeadlineAt: checkinResult.nextDeadlineAt,
        }, 200, req);
      }

      return new Response(
        `<!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>obold — Check-in Confirmed</title>
          <style>
            body { background: #07090e; color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
            .card { background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 40px; text-align: center; max-width: 480px; box-shadow: 0 20px 40px rgba(0,0,0,0.5); }
            .badge { display: inline-block; background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 9999px; padding: 6px 16px; font-size: 13px; font-weight: 600; margin-bottom: 20px; }
            h1 { margin: 0 0 12px 0; font-size: 24px; font-weight: 700; }
            p { color: #9ca3af; margin: 0 0 24px 0; font-size: 15px; line-height: 1.5; }
            .time-box { background: rgba(0, 0, 0, 0.4); border: 1px solid rgba(255,255,255,0.06); padding: 14px; border-radius: 10px; font-family: monospace; font-size: 14px; color: #38bdf8; margin-bottom: 20px; }
            .footer { font-size: 12px; color: #6b7280; }
          </style>
        </head>
        <body>
          <div class="card">
            <div class="badge">✓ TOKEN BURNED & VERIFIED</div>
            <h1>Heartbeat Confirmed</h1>
            <p>Your dead man switch [<strong>${this.escapeHtml(verification.switchId)}</strong>] has been reset.</p>
            <div class="time-box">Next Deadline: ${deadlineStr}</div>
            <div class="footer">obold Sovereign Daemon • BCN Studio (<a href="https://bcnstudio.tech" style="color:#38bdf8;text-decoration:none;">bcnstudio.tech</a>)</div>
          </div>
        </body>
        </html>`,
        { status: 200, headers: baseHeaders }
      );
    } catch (err: any) {
      if (isJsonAccept) {
        return this.jsonResponse({ error: err.message }, 400, req);
      }
      return new Response(
        `<!DOCTYPE html><html><body style="background:#0a0c10;color:#facc15;font-family:sans-serif;text-align:center;padding:50px;">
          <h2>⚠️ Check-In Failed</h2>
          <p>${this.escapeHtml(err.message)}</p>
        </body></html>`,
        { status: 400, headers: baseHeaders }
      );
    }
  }

  private jsonResponse(data: any, status: number = 200, req?: Request): Response {
    const corsHeaders = req ? this.getCorsHeaders(req) : {};
    return new Response(JSON.stringify(data), {
      status,
      headers: {
        'Content-Type': 'application/json',
        ...corsHeaders,
      },
    });
  }
}
