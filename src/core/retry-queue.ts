import type { OboldDatabase } from '../db/database.ts';
import type { LedgerRecord } from '../config/types.ts';

export class DeadLetterRetryQueue {
  private db: OboldDatabase;
  private baseDelayMs: number;
  private maxDelayMs: number;
  private maxWindowMs: number;

  constructor(
    db: OboldDatabase,
    baseDelayMs: number = 5000,
    maxDelayMs: number = 21600000,
    maxWindowMs: number = 259200000
  ) {
    this.db = db;
    this.baseDelayMs = baseDelayMs;
    this.maxDelayMs = maxDelayMs;
    this.maxWindowMs = maxWindowMs;
  }

  public calculateNextRetry(attempt: number, createdAt: number): number | null {
    const now = Date.now();

    if (now - createdAt >= this.maxWindowMs) {
      return null;
    }

    const expDelay = Math.min(this.maxDelayMs, this.baseDelayMs * Math.pow(2, attempt));
    const jitterFactor = 0.5 + Math.random() * 0.5;
    const finalDelay = Math.round(expDelay * jitterFactor);
    const nextRetryAt = now + finalDelay;

    if (nextRetryAt - createdAt > this.maxWindowMs) {
      return null;
    }

    return nextRetryAt;
  }

  public getDueRetries(): LedgerRecord[] {
    const now = Date.now();
    const all = this.db.getPendingOrRetryableLedgerEntries();
    return all.filter((entry) => entry.nextRetryAt && entry.nextRetryAt <= now);
  }
}
