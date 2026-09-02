export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  retryAfterSec: number;
}

export class InMemoryRateLimiter {
  private buckets = new Map<string, { count: number; resetAt: number }>();
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;
  private trustedProxies: Set<string>;

  constructor(cleanupIntervalMs: number = 60000, trustedProxies?: string[]) {
    this.cleanupTimer = setInterval(() => this.cleanup(), cleanupIntervalMs);
    const defaults = ['127.0.0.1', '::1', 'localhost'];
    const list = trustedProxies && trustedProxies.length > 0 ? trustedProxies : defaults;
    this.trustedProxies = new Set(list.map((p) => p.trim().toLowerCase()));
  }

  public consume(key: string, limit: number, windowMs: number): RateLimitResult {
    const now = Date.now();
    const bucket = this.buckets.get(key);

    if (!bucket || now >= bucket.resetAt) {
      const resetAt = now + windowMs;
      this.buckets.set(key, { count: 1, resetAt });
      return {
        allowed: true,
        remaining: Math.max(0, limit - 1),
        resetAt,
        retryAfterSec: 0,
      };
    }

    if (bucket.count >= limit) {
      const retryAfterSec = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
      return {
        allowed: false,
        remaining: 0,
        resetAt: bucket.resetAt,
        retryAfterSec,
      };
    }

    bucket.count += 1;
    return {
      allowed: true,
      remaining: Math.max(0, limit - bucket.count),
      resetAt: bucket.resetAt,
      retryAfterSec: 0,
    };
  }

  public getClientIp(req: Request, directSocketIp: string = '127.0.0.1'): string {
    const isDirectSocketTrusted = this.trustedProxies.has(directSocketIp.toLowerCase()) || directSocketIp === '127.0.0.1' || directSocketIp === '::1';

    if (isDirectSocketTrusted) {
      const cfIp = req.headers.get('cf-connecting-ip');
      if (cfIp) return cfIp.trim();

      const xForwarded = req.headers.get('x-forwarded-for');
      if (xForwarded) {
        const first = xForwarded.split(',')[0];
        if (first) return first.trim();
      }

      const xReal = req.headers.get('x-real-ip');
      if (xReal) return xReal.trim();
    }

    return directSocketIp;
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, bucket] of this.buckets.entries()) {
      if (now >= bucket.resetAt) {
        this.buckets.delete(key);
      }
    }
  }

  public destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.buckets.clear();
  }
}
