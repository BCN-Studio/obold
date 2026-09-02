import { Database } from 'bun:sqlite';
import { dirname } from 'node:path';
import { mkdirSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { SCHEMA_SQL } from './schema.ts';
import type { LedgerRecord, HeartbeatToken, LogLevel, SwitchRow, AuditLogRow, HeartbeatTokenRow, ExecutionLedgerRow } from '../config/types.ts';
import type { OboldCipher } from '../crypto/cipher.ts';

export class OboldDatabase {
  private db: Database;
  private dbPath: string;

  constructor(dbPath: string = './data/obold.db', walMode: boolean = true) {
    this.dbPath = dbPath;

    const dir = dirname(dbPath);
    if (dir && dir !== '.') {
      mkdirSync(dir, { recursive: true });
    }

    this.db = new Database(dbPath, { create: true });

    if (walMode) {
      this.db.exec('PRAGMA journal_mode = WAL;');
    }
    this.db.exec('PRAGMA synchronous = NORMAL;');
    this.db.exec('PRAGMA busy_timeout = 5000;');
    this.db.exec('PRAGMA foreign_keys = ON;');

    this.initSchema();
  }

  private initSchema(): void {
    this.db.exec(SCHEMA_SQL);
    try {
      this.db.exec('ALTER TABLE switches ADD COLUMN paused_until INTEGER DEFAULT NULL;');
    } catch {}
    try {
      this.db.exec('ALTER TABLE switches ADD COLUMN pause_reason TEXT DEFAULT NULL;');
    } catch {}
    try {
      this.db.exec('ALTER TABLE switches ADD COLUMN plan_hash TEXT DEFAULT NULL;');
    } catch {}
    try {
      this.db.exec('ALTER TABLE switches ADD COLUMN frozen_plan TEXT DEFAULT NULL;');
    } catch {}
    try {
      this.db.exec('ALTER TABLE execution_ledger ADD COLUMN idempotency_key TEXT DEFAULT NULL;');
    } catch {}
    this.setMetadata('schema_version', '1.0.0');
  }

  public close(): void {
    this.db.close();
  }

  public checkpoint(): void {
    try {
      this.db.exec('PRAGMA wal_checkpoint(PASSIVE);');
    } catch {
      
    }
  }

  public setMetadata(key: string, value: string): void {
    const query = this.db.query(`
      INSERT INTO system_metadata (key, value, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at;
    `);
    query.run(key, value, Date.now());
  }

  public getMetadata(key: string): string | null {
    const query = this.db.query<{ value: string }, [string]>(`
      SELECT value FROM system_metadata WHERE key = ?;
    `);
    const row = query.get(key);
    return row ? row.value : null;
  }

  public logAudit(
    level: LogLevel,
    category: string,
    message: string,
    metadata?: Record<string, any>,
    switchId?: string
  ): void {
    const id = `aud-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const resolvedSwitchId = switchId || (metadata && typeof metadata === 'object' && metadata.switchId ? String(metadata.switchId) : null);
    const sanitizedMetadata = metadata ? this.redactSensitive(metadata) : null;
    const query = this.db.query(`
      INSERT INTO audit_log (id, level, category, switch_id, message, metadata, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?);
    `);
    query.run(
      id,
      level,
      category,
      resolvedSwitchId,
      message,
      sanitizedMetadata ? JSON.stringify(sanitizedMetadata) : null,
      Date.now()
    );
  }

  private redactSensitive(obj: any): any {
    if (obj === null || obj === undefined) return obj;
    if (typeof obj !== 'object') return obj;
    if (Array.isArray(obj)) return obj.map((item) => this.redactSensitive(item));

    const result: Record<string, any> = {};
    const pattern = /password|token|secret|private[_-]?key|api[_-]?key|access[_-]?key|secret[_-]?key|seed|share|pin|auth/i;

    for (const [key, value] of Object.entries(obj)) {
      if (pattern.test(key)) {
        result[key] = '[REDACTED]';
      } else if (typeof value === 'object' && value !== null) {
        result[key] = this.redactSensitive(value);
      } else {
        result[key] = value;
      }
    }
    return result;
  }

  public getAuditLogs(limit: number = 100, switchId?: string): AuditLogRow[] {
    if (switchId) {
      const query = this.db.query<AuditLogRow, [string, number]>(`
        SELECT * FROM audit_log WHERE switch_id = ? ORDER BY created_at DESC LIMIT ?;
      `);
      return query.all(switchId, limit);
    }
    const query = this.db.query<AuditLogRow, [number]>(`
      SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?;
    `);
    return query.all(limit);
  }

  public upsertSwitch(
    id: string,
    name: string,
    status: string,
    lastCheckinAt: number,
    nextDeadlineAt: number,
    activeStageIndex: number = -1,
    stageTriggeredAt: number | null = null,
    planHash?: string | null,
    frozenPlan?: string | null
  ): void {
    const now = Date.now();
    const query = this.db.query(`
      INSERT INTO switches (id, name, status, last_checkin_at, next_deadline_at, active_stage_index, stage_triggered_at, plan_hash, frozen_plan, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        status = excluded.status,
        last_checkin_at = excluded.last_checkin_at,
        next_deadline_at = excluded.next_deadline_at,
        active_stage_index = excluded.active_stage_index,
        stage_triggered_at = excluded.stage_triggered_at,
        plan_hash = COALESCE(excluded.plan_hash, switches.plan_hash),
        frozen_plan = COALESCE(excluded.frozen_plan, switches.frozen_plan),
        updated_at = excluded.updated_at;
    `);
    query.run(id, name, status, lastCheckinAt, nextDeadlineAt, activeStageIndex, stageTriggeredAt, planHash || null, frozenPlan || null, now, now);
  }

  public getSwitch(id: string): SwitchRow | null {
    const query = this.db.query<SwitchRow, [string]>(`SELECT * FROM switches WHERE id = ?;`);
    return query.get(id);
  }

  public getAllSwitches(): SwitchRow[] {
    const query = this.db.query<SwitchRow, []>(`SELECT * FROM switches ORDER BY next_deadline_at ASC;`);
    return query.all();
  }

  public updateSwitchStatus(
    id: string,
    status: string,
    activeStageIndex?: number,
    stageTriggeredAt?: number | null
  ): void {
    const now = Date.now();
    if (activeStageIndex !== undefined && stageTriggeredAt !== undefined) {
      const query = this.db.query(`
        UPDATE switches
        SET status = ?, active_stage_index = ?, stage_triggered_at = ?, updated_at = ?
        WHERE id = ?;
      `);
      query.run(status, activeStageIndex, stageTriggeredAt, now, id);
    } else if (activeStageIndex !== undefined) {
      const query = this.db.query(`
        UPDATE switches
        SET status = ?, active_stage_index = ?, updated_at = ?
        WHERE id = ?;
      `);
      query.run(status, activeStageIndex, now, id);
    } else {
      const query = this.db.query(`
        UPDATE switches
        SET status = ?, updated_at = ?
        WHERE id = ?;
      `);
      query.run(status, now, id);
    }
  }

  public pauseSwitch(id: string, pausedUntil?: number | null, reason?: string | null): boolean {
    const sw = this.getSwitch(id);
    if (!sw) return false;
    const now = Date.now();
    const query = this.db.query(`
      UPDATE switches
      SET status = 'PAUSED', paused_until = ?, pause_reason = ?, updated_at = ?
      WHERE id = ?;
    `);
    query.run(pausedUntil || null, reason || null, now, id);
    this.logAudit('WARN', 'SWITCH_PAUSED', `Switch "${sw.name}" (${id}) entered vacation/maintenance pause mode.`, {
      switchId: id,
      pausedUntil: pausedUntil ? new Date(pausedUntil).toISOString() : 'indefinite',
      reason: reason || 'none',
    }, id);
    return true;
  }

  public resumeSwitch(id: string, newDeadlineAt?: number): boolean {
    const sw = this.getSwitch(id);
    if (!sw) return false;
    const now = Date.now();
    const deadline = newDeadlineAt || (now + Math.max(60000, sw.next_deadline_at - sw.last_checkin_at));
    const query = this.db.query(`
      UPDATE switches
      SET status = 'ARMED', paused_until = NULL, pause_reason = NULL, next_deadline_at = ?, last_checkin_at = ?, updated_at = ?
      WHERE id = ?;
    `);
    query.run(deadline, now, now, id);
    this.logAudit('INFO', 'SWITCH_RESUMED', `Switch "${sw.name}" (${id}) resumed active countdown.`, {
      switchId: id,
      nextDeadlineAt: new Date(deadline).toISOString(),
    }, id);
    return true;
  }

  
  public saveHeartbeatToken(token: HeartbeatToken): void {
    const query = this.db.query(`
      INSERT INTO heartbeat_tokens (id, switch_id, token_hash, expires_at, used_at, is_duress, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?);
    `);
    query.run(
      token.id,
      token.switchId,
      token.tokenHash,
      token.expiresAt,
      token.usedAt || null,
      token.isDuress ? 1 : 0,
      token.createdAt
    );
  }

  public findTokenByHash(tokenHash: string): HeartbeatToken | null {
    const query = this.db.query<{
      id: string;
      switch_id: string;
      token_hash: string;
      expires_at: number;
      used_at: number | null;
      is_duress: number;
      created_at: number;
    }, [string]>(`
      SELECT * FROM heartbeat_tokens WHERE token_hash = ?;
    `);
    const row = query.get(tokenHash);
    if (!row) return null;

    return {
      id: row.id,
      switchId: row.switch_id,
      tokenHash: row.token_hash,
      expiresAt: row.expires_at,
      usedAt: row.used_at,
      isDuress: row.is_duress === 1,
      createdAt: row.created_at,
    };
  }

  
  public markTokenUsed(tokenHash: string): boolean {
    const now = Date.now();
    const query = this.db.query(`
      UPDATE heartbeat_tokens
      SET used_at = ?
      WHERE token_hash = ? AND used_at IS NULL;
    `);
    const result = query.run(now, tokenHash);
    return result.changes > 0;
  }

  public atomicCheckinWithToken(
    tokenHash: string,
    switchId: string,
    switchName: string,
    intervalMs: number,
    planHash?: string | null,
    frozenPlan?: string | null
  ): { success: boolean; nextDeadlineAt: number; isDuress: boolean } {
    const tx = this.db.transaction(() => {
      const now = Date.now();
      const tokenQuery = this.db.query<{
        id: string;
        switch_id: string;
        expires_at: number;
        used_at: number | null;
        is_duress: number;
      }, [string]>(`SELECT * FROM heartbeat_tokens WHERE token_hash = ?;`);
      const tokenRow = tokenQuery.get(tokenHash);

      if (!tokenRow) {
        throw new Error('Token not found');
      }
      if (tokenRow.used_at !== null) {
        throw new Error('Token already used or expired');
      }
      if (tokenRow.expires_at <= now) {
        throw new Error('Token already used or expired');
      }
      if (tokenRow.switch_id !== switchId) {
        throw new Error(`Token does not match switch ID ${switchId}`);
      }

      const updateToken = this.db.query(`
        UPDATE heartbeat_tokens
        SET used_at = ?
        WHERE token_hash = ? AND used_at IS NULL;
      `);
      const updateRes = updateToken.run(now, tokenHash);
      if (updateRes.changes === 0) {
        throw new Error('Token already used or expired');
      }

      const nextDeadlineAt = now + intervalMs;
      const upsertSwitch = this.db.query(`
        INSERT INTO switches (id, name, status, last_checkin_at, next_deadline_at, active_stage_index, stage_triggered_at, plan_hash, frozen_plan, created_at, updated_at)
        VALUES (?, ?, 'ARMED', ?, ?, -1, NULL, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          name = excluded.name,
          status = 'ARMED',
          last_checkin_at = excluded.last_checkin_at,
          next_deadline_at = excluded.next_deadline_at,
          active_stage_index = -1,
          stage_triggered_at = NULL,
          plan_hash = COALESCE(excluded.plan_hash, switches.plan_hash),
          frozen_plan = COALESCE(excluded.frozen_plan, switches.frozen_plan),
          updated_at = excluded.updated_at;
      `);
      upsertSwitch.run(switchId, switchName, now, nextDeadlineAt, planHash || null, frozenPlan || null, now, now);

      return { success: true, nextDeadlineAt, isDuress: tokenRow.is_duress === 1 };
    });

    return tx();
  }

  
  public insertLedgerEntry(entry: LedgerRecord): void {
    const query = this.db.query(`
      INSERT INTO execution_ledger (
        id, switch_id, stage_id, action_id, plugin, state, idempotency_key,
        attempt_count, max_attempts, next_retry_at, last_error,
        payload_snapshot, result_snapshot, created_at, updated_at,
        dispatched_at, acknowledged_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    `);
    query.run(
      entry.id,
      entry.switchId,
      entry.stageId,
      entry.actionId,
      entry.plugin,
      entry.state,
      entry.idempotencyKey || null,
      entry.attemptCount,
      entry.maxAttempts,
      entry.nextRetryAt || null,
      entry.lastError || null,
      entry.payloadSnapshot || null,
      entry.resultSnapshot || null,
      entry.createdAt,
      entry.updatedAt,
      entry.dispatchedAt || null,
      entry.acknowledgedAt || null
    );
  }

  public updateLedgerEntry(entry: Partial<LedgerRecord> & { id: string }): void {
    const now = Date.now();
    const existing = this.getLedgerEntry(entry.id);
    if (!existing) return;

    const merged = { ...existing, ...entry, updatedAt: now };
    const query = this.db.query(`
      UPDATE execution_ledger
      SET state = ?, idempotency_key = ?, attempt_count = ?, next_retry_at = ?, last_error = ?,
          result_snapshot = ?, updated_at = ?, dispatched_at = ?, acknowledged_at = ?
      WHERE id = ?;
    `);
    query.run(
      merged.state,
      merged.idempotencyKey || null,
      merged.attemptCount,
      merged.nextRetryAt || null,
      merged.lastError || null,
      merged.resultSnapshot || null,
      merged.updatedAt,
      merged.dispatchedAt || null,
      merged.acknowledgedAt || null,
      entry.id
    );
  }

  public getLedgerEntry(id: string): LedgerRecord | null {
    const query = this.db.query<ExecutionLedgerRow, [string]>(`SELECT * FROM execution_ledger WHERE id = ?;`);
    const row = query.get(id);
    if (!row) return null;
    return this.mapLedgerRow(row);
  }

  public getPendingOrRetryableLedgerEntries(): LedgerRecord[] {
    const query = this.db.query<ExecutionLedgerRow, []>(`
      SELECT * FROM execution_ledger
      WHERE state IN ('PENDING', 'CLAIMED', 'EXECUTING', 'FAILED_RETRYABLE', 'UNKNOWN', 'ARMED', 'DISPATCHED')
         OR (state IN ('FAILED', 'FAILED_RETRYABLE') AND attempt_count < max_attempts)
      ORDER BY created_at ASC;
    `);
    return query.all().map((r) => this.mapLedgerRow(r));
  }

  public getRecentLedgerEntries(limit: number = 50): LedgerRecord[] {
    const query = this.db.query<ExecutionLedgerRow, [number]>(`
      SELECT * FROM execution_ledger ORDER BY created_at DESC LIMIT ?;
    `);
    return query.all(limit).map((r) => this.mapLedgerRow(r));
  }

  public abortLedgerEntriesForSwitch(switchId: string, reason: string): number {
    const now = Date.now();
    const query = this.db.query(`
      UPDATE execution_ledger
      SET state = 'FAILED_PERMANENT', next_retry_at = NULL, last_error = ?, updated_at = ?
      WHERE switch_id = ? AND state IN ('PENDING', 'CLAIMED', 'EXECUTING', 'FAILED_RETRYABLE', 'UNKNOWN', 'ARMED', 'DISPATCHED');
    `);
    const result = query.run(`Execution aborted: ${reason}`, now, switchId);
    return result.changes;
  }

  public getOrGenerateKdfSalt(): string {
    const existing = this.getMetadata('kdf_salt');
    if (existing && existing.length > 0) {
      return existing;
    }
    const newSalt = randomBytes(32).toString('hex');
    this.setMetadata('kdf_salt', newSalt);
    return newSalt;
  }

  public rekeyDatabase(oldCipher: OboldCipher, newCipher: OboldCipher): { reencryptedRecords: number } {
    const allRows = this.db.query<ExecutionLedgerRow, []>(`SELECT * FROM execution_ledger;`).all();

    for (const row of allRows) {
      const payloadAad = row.idempotency_key ? `${row.switch_id}:${row.stage_id}:${row.action_id}:${row.plugin}:${row.idempotency_key}:v1` : `${row.switch_id}:${row.stage_id}:${row.action_id}:${row.plugin}:v1`;
      const resultAad = row.idempotency_key ? `${row.switch_id}:${row.stage_id}:${row.action_id}:${row.plugin}:${row.idempotency_key}:res:v1` : `${row.switch_id}:${row.stage_id}:${row.action_id}:${row.plugin}:res:v1`;

      if (row.payload_snapshot && row.payload_snapshot.startsWith('enc:')) {
        try {
          oldCipher.decryptFromString(row.payload_snapshot, payloadAad);
        } catch (err: any) {
          throw new Error(`Failed to decrypt payload for ledger entry ${row.id} with old key: ${err.message}`);
        }
      }
      if (row.result_snapshot && row.result_snapshot.startsWith('enc:')) {
        try {
          oldCipher.decryptFromString(row.result_snapshot, resultAad);
        } catch (err: any) {
          throw new Error(`Failed to decrypt result snapshot for ledger entry ${row.id} with old key: ${err.message}`);
        }
      }
    }

    let count = 0;
    const updateStmt = this.db.prepare(`
      UPDATE execution_ledger
      SET payload_snapshot = ?, result_snapshot = ?, updated_at = ?
      WHERE id = ?;
    `);

    const rekeyTx = this.db.transaction(() => {
      const now = Date.now();
      for (const row of allRows) {
        const payloadAad = row.idempotency_key ? `${row.switch_id}:${row.stage_id}:${row.action_id}:${row.plugin}:${row.idempotency_key}:v1` : `${row.switch_id}:${row.stage_id}:${row.action_id}:${row.plugin}:v1`;
        const resultAad = row.idempotency_key ? `${row.switch_id}:${row.stage_id}:${row.action_id}:${row.plugin}:${row.idempotency_key}:res:v1` : `${row.switch_id}:${row.stage_id}:${row.action_id}:${row.plugin}:res:v1`;

        let newPayload = row.payload_snapshot;
        let newResult = row.result_snapshot;
        let changed = false;

        if (row.payload_snapshot && row.payload_snapshot.startsWith('enc:')) {
          const plain = oldCipher.decryptFromString(row.payload_snapshot, payloadAad);
          newPayload = newCipher.encryptToString(plain, payloadAad);
          changed = true;
        }

        if (row.result_snapshot && row.result_snapshot.startsWith('enc:')) {
          const plain = oldCipher.decryptFromString(row.result_snapshot, resultAad);
          newResult = newCipher.encryptToString(plain, resultAad);
          changed = true;
        }

        if (changed) {
          updateStmt.run(newPayload, newResult, now, row.id);
          count++;
        }
      }

      this.setMetadata('master_key_last_rotated_at', Date.now().toString());
      this.logAudit('INFO', 'MASTER_KEY_ROTATED', `Master encryption key rotated. Re-encrypted ${count} ledger records.`);
    });

    rekeyTx();
    this.checkpoint();
    return { reencryptedRecords: count };
  }

  public getSqlite(): Database {
    return this.db;
  }

  public checkIntegrity(): { integrity: string; journalMode: string } {
    const integrityRow = this.db.query<{ integrity_check: string }, []>('PRAGMA integrity_check;').get();
    const journalRow = this.db.query<{ journal_mode: string }, []>('PRAGMA journal_mode;').get();
    return {
      integrity: integrityRow?.integrity_check || 'unknown',
      journalMode: journalRow?.journal_mode || 'unknown',
    };
  }

  private mapLedgerRow(row: ExecutionLedgerRow): LedgerRecord {
    return {
      id: row.id,
      switchId: row.switch_id,
      stageId: row.stage_id,
      actionId: row.action_id,
      plugin: row.plugin,
      state: row.state,
      idempotencyKey: row.idempotency_key || null,
      attemptCount: row.attempt_count,
      maxAttempts: row.max_attempts,
      nextRetryAt: row.next_retry_at,
      lastError: row.last_error,
      payloadSnapshot: row.payload_snapshot,
      resultSnapshot: row.result_snapshot,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      dispatchedAt: row.dispatched_at,
      acknowledgedAt: row.acknowledged_at,
    };
  }
}
