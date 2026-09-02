import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { Server } from 'bun';
import type { OboldConfig } from '../config/types.ts';
import type { OboldEngine } from '../core/engine.ts';
import type { OboldTokenManager } from '../crypto/token.ts';
import { SseEventBus } from './sse.ts';
import { HealthHandler } from './health.ts';
import { ApiRouter } from './api.ts';

export class OboldServer {
  private config: OboldConfig;
  private engine: OboldEngine;
  private tokenManager: OboldTokenManager;
  private sseBus: SseEventBus;
  private healthHandler: HealthHandler;
  private apiRouter: ApiRouter;
  private server: Server<any> | null = null;

  constructor(config: OboldConfig, engine: OboldEngine, tokenManager: OboldTokenManager) {
    this.config = config;
    this.engine = engine;
    this.tokenManager = tokenManager;
    this.sseBus = new SseEventBus();
    this.healthHandler = new HealthHandler(engine);
    this.apiRouter = new ApiRouter(
      engine,
      tokenManager,
      this.sseBus,
      this.healthHandler,
      config.server
    );
  }

  public start(): Server<any> {
    const host = this.config.server.host || '127.0.0.1';
    const port = this.config.server.port || 8080;

    const isLoopback = host === '127.0.0.1' || host === 'localhost' || host === '::1';
    const hasValidToken = typeof this.config.server.apiAuthToken === 'string' && this.config.server.apiAuthToken.trim().length > 0;

    if (!isLoopback && !hasValidToken && !process.env.OBOLD_UNSAFE_BIND) {
      const errMsg = `Refusing to bind HTTP server to remote interface "${host}" without API authentication configured. Set "server.apiAuthToken" in your config or pass OBOLD_UNSAFE_BIND=1.`;
      this.engine.getDb().logAudit('FATAL', 'SECURITY_UNSAFE_BIND', errMsg);
      throw new Error(errMsg);
    }

    this.server = Bun.serve({
      hostname: host,
      port,
      fetch: async (req) => {
        const url = new URL(req.url);
        const path = url.pathname;

        if (path === '/' || path === '/index.html' || path === '/dashboard') {
          return this.serveStaticFile('src/ui/index.html', 'text/html; charset=utf-8');
        }
        if (path === '/ui/styles.css' || path === '/styles.css') {
          return this.serveStaticFile('src/ui/styles.css', 'text/css; charset=utf-8');
        }
        if (path === '/ui/app.js' || path === '/app.js') {
          return this.serveStaticFile('src/ui/app.js', 'application/javascript; charset=utf-8');
        }

        return this.apiRouter.handleRequest(req);
      },
    });

    this.engine.getDb().logAudit('INFO', 'SERVER_START', `obold HTTP Server running at http://${host}:${port}`);
    return this.server;
  }

  public stop(): void {
    if (this.server) {
      this.server.stop();
      this.server = null;
      this.apiRouter.destroy();
      this.engine.getDb().logAudit('INFO', 'SERVER_STOP', 'obold HTTP Server stopped.');
    }
  }

  private serveStaticFile(relativePath: string, contentType: string): Response {
    const fullPath = join(process.cwd(), relativePath);
    if (!existsSync(fullPath)) {
      return new Response(`File not found: ${relativePath}`, { status: 404 });
    }
    const content = readFileSync(fullPath, 'utf-8');
    return new Response(content, {
      status: 200,
      headers: {
        'Content-Type': contentType,
        'Cache-Control': 'public, max-age=3600',
      },
    });
  }

  public getPort(): number {
    return this.server?.port || this.config.server.port;
  }
}
