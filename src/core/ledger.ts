import { randomUUID } from 'node:crypto';
import type { OboldDatabase } from '../db/database.ts';
import type { LedgerRecord, LedgerState, ExecutionResult, DeliveryErrorType } from '../config/types.ts';
import type { OboldCipher } from '../crypto/cipher.ts';

export class AtomicExecutionLedger {
  private db: OboldDatabase;
  private cipher: OboldCipher;
  private activeLeases = new Map<string, number>();

  constructor(db: OboldDatabase, cipher: OboldCipher) {
    this.db = db;
    this.cipher = cipher;
  }

  public acquireLease(id: string, leaseDurationMs: number = 35000): boolean {
    const now = Date.now();
    const currentExpiry = this.activeLeases.get(id);
    if (currentExpiry && currentExpiry > now) {
      return false;
    }
    this.activeLeases.set(id, now + leaseDurationMs);
    return true;
  }

  public hasActiveLease(id: string): boolean {
    const now = Date.now();
    const expiry = this.activeLeases.get(id);
    if (!expiry) return false;
    if (expiry <= now) {
      this.activeLeases.delete(id);
      return false;
    }
    return true;
  }

  public releaseLease(id: string): void {
    this.activeLeases.delete(id);
  }

  public releaseAllLeases(): void {
    this.activeLeases.clear();
  }

  public createEntry(
    switchId: string,
    stageId: string,
    actionId: string,
    plugin: string,
    rawConfig: Record<string, any>,
    maxAttempts: number = 10,
    customIdempotencyKey?: string
  ): LedgerRecord {
    const id = `led-${switchId}-${stageId}-${actionId}-${Date.now()}`;
    const now = Date.now();
    const idempotencyKey = customIdempotencyKey || `idemp-${randomUUID()}`;
    const aad = `${switchId}:${stageId}:${actionId}:${plugin}:${idempotencyKey}:v1`;
    const payloadSnapshot = this.cipher.encryptToString(rawConfig, aad);

    const entry: LedgerRecord = {
      id,
      switchId,
      stageId,
      actionId,
      plugin,
      state: 'PENDING',
      idempotencyKey,
      attemptCount: 0,
      maxAttempts,
      payloadSnapshot,
      createdAt: now,
      updatedAt: now,
    };

    this.db.insertLedgerEntry(entry);
    this.db.logAudit(
      'INFO',
      'LEDGER_INIT',
      `Action ${actionId} (${plugin}) initialized in PENDING state. IdempotencyKey: ${idempotencyKey}`,
      { id, switchId, idempotencyKey },
      switchId
    );
    return entry;
  }

  public claimEntry(id: string): void {
    this.db.updateLedgerEntry({
      id,
      state: 'CLAIMED',
      updatedAt: Date.now(),
    });
  }

  public armEntry(id: string): void {
    this.claimEntry(id);
  }

  public markExecuting(id: string, leaseDurationMs: number = 35000): void {
    this.acquireLease(id, leaseDurationMs);
    this.db.updateLedgerEntry({
      id,
      state: 'EXECUTING',
      dispatchedAt: Date.now(),
      updatedAt: Date.now(),
    });
  }

  public markDispatched(id: string): void {
    this.markExecuting(id);
  }

  public markSucceeded(id: string, result: ExecutionResult): void {
    this.releaseLease(id);
    const existing = this.db.getLedgerEntry(id);
    const aad = existing ? (existing.idempotencyKey ? `${existing.switchId}:${existing.stageId}:${existing.actionId}:${existing.plugin}:${existing.idempotencyKey}:res:v1` : `${existing.switchId}:${existing.stageId}:${existing.actionId}:${existing.plugin}:res:v1`) : undefined;
    const resultSnapshot = this.cipher.encryptToString(result, aad);
    this.db.updateLedgerEntry({
      id,
      state: 'SUCCEEDED',
      resultSnapshot,
      acknowledgedAt: Date.now(),
      nextRetryAt: null,
      lastError: null,
      updatedAt: Date.now(),
    });
    this.db.logAudit(
      'INFO',
      'EXECUTION_SUCCEEDED',
      `Action ${result.actionId} (${result.plugin}) SUCCEEDED in ${result.durationMs}ms.`,
      { id, actionId: result.actionId, durationMs: result.durationMs },
      existing?.switchId
    );
  }

  public markAcknowledged(id: string, result: ExecutionResult): void {
    this.markSucceeded(id, result);
  }

  public markBlockedMissingPlugin(id: string, pluginName: string): void {
    this.releaseLease(id);
    const existing = this.db.getLedgerEntry(id);
    const errorMsg = `CRITICAL: Emergency execution blocked because required plugin "${pluginName}" is not registered or unavailable.`;
    this.db.updateLedgerEntry({
      id,
      state: 'BLOCKED_PLUGIN_MISSING',
      lastError: errorMsg,
      nextRetryAt: null,
      updatedAt: Date.now(),
    });

    this.db.logAudit(
      'FATAL',
      'BLOCKED_PLUGIN_MISSING',
      errorMsg,
      { id, actionId: existing?.actionId, plugin: pluginName },
      existing?.switchId
    );
  }

  public markFailed(
    id: string,
    errorMsg: string,
    failureType: DeliveryErrorType = 'TRANSIENT',
    nextRetryAt: number | null = null
  ): void {
    this.releaseLease(id);
    const existing = this.db.getLedgerEntry(id);
    const attemptCount = (existing?.attemptCount || 0) + 1;
    const isExhausted = existing ? attemptCount >= existing.maxAttempts : false;

    let targetState: LedgerState = 'FAILED_RETRYABLE';
    if (failureType === 'PERMANENT' || isExhausted) {
      targetState = 'FAILED_PERMANENT';
    } else if (failureType === 'UNKNOWN') {
      targetState = 'UNKNOWN';
    }

    this.db.updateLedgerEntry({
      id,
      state: targetState,
      attemptCount,
      lastError: errorMsg,
      nextRetryAt: targetState === 'FAILED_PERMANENT' ? null : nextRetryAt,
      updatedAt: Date.now(),
    });

    this.db.logAudit(
      failureType === 'PERMANENT' || isExhausted ? 'ERROR' : 'WARN',
      'EXECUTION_FAILED',
      `Action ${existing?.actionId || id} failed attempt ${attemptCount} [${failureType}]. State: ${targetState}. Next retry: ${
        nextRetryAt && targetState !== 'FAILED_PERMANENT' ? new Date(nextRetryAt).toISOString() : 'NONE'
      }`,
      { error: errorMsg, failureType, attemptCount, targetState },
      existing?.switchId
    );
  }

  public getRecoverableEntries(): LedgerRecord[] {
    return this.db.getPendingOrRetryableLedgerEntries();
  }

  public getDecryptedPayload(entry: LedgerRecord): Record<string, any> {
    if (!entry.payloadSnapshot) return {};
    try {
      const aad = entry.idempotencyKey ? `${entry.switchId}:${entry.stageId}:${entry.actionId}:${entry.plugin}:${entry.idempotencyKey}:v1` : `${entry.switchId}:${entry.stageId}:${entry.actionId}:${entry.plugin}:v1`;
      const decryptedStr = this.cipher.decryptFromString(entry.payloadSnapshot, aad);
      return JSON.parse(decryptedStr);
    } catch {
      return {};
    }
  }

  public getDecryptedResult(entry: LedgerRecord): ExecutionResult | null {
    if (!entry.resultSnapshot) return null;
    try {
      const aad = entry.idempotencyKey ? `${entry.switchId}:${entry.stageId}:${entry.actionId}:${entry.plugin}:${entry.idempotencyKey}:res:v1` : `${entry.switchId}:${entry.stageId}:${entry.actionId}:${entry.plugin}:res:v1`;
      const decryptedStr = this.cipher.decryptFromString(entry.resultSnapshot, aad);
      return JSON.parse(decryptedStr);
    } catch {
      return null;
    }
  }
}
