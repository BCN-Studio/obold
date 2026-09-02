import { EventEmitter } from 'node:events';
import { randomUUID, createHash } from 'node:crypto';
import type {
  OboldConfig,
  SwitchConfig,
  StageConfig,
  PluginActionConfig,
  SwitchRuntimeState,
  SwitchRow,
  ExecutionResult,
  DeliveryErrorType,
  ExecutionContract,
} from '../config/types.ts';
import type { OboldDatabase } from '../db/database.ts';
import type { OboldCipher } from '../crypto/cipher.ts';
import type { PluginRegistry } from '../plugins/registry.ts';
import { AtomicExecutionLedger } from './ledger.ts';
import { DeadLetterRetryQueue } from './retry-queue.ts';

export class OboldEngine extends EventEmitter {
  private config: OboldConfig;
  private db: OboldDatabase;
  private cipher: OboldCipher;
  private plugins: PluginRegistry;
  private ledger: AtomicExecutionLedger;
  private retryQueue: DeadLetterRetryQueue;

  private tickInterval: ReturnType<typeof setInterval> | null = null;
  private lastTickTime: number = Date.now();
  private monotonicStart: bigint = process.hrtime.bigint();
  private lastMonotonicTick: bigint = process.hrtime.bigint();
  private sentReminders = new Map<string, Set<string>>();
  private activeSwitchTicks = new Set<string>();
  private isProcessingRetries: boolean = false;
  private activeControllers = new Map<string, Set<AbortController>>();

  constructor(
    config: OboldConfig,
    db: OboldDatabase,
    cipher: OboldCipher,
    plugins: PluginRegistry
  ) {
    super();
    this.config = config;
    this.db = db;
    this.cipher = cipher;
    this.plugins = plugins;
    this.ledger = new AtomicExecutionLedger(db, cipher);
    this.retryQueue = new DeadLetterRetryQueue(db);

    this.syncSwitchesWithDb();
  }

  public static computePlanHash(sw: SwitchConfig): string {
    const canonical = {
      id: sw.id,
      name: sw.name,
      intervalMs: sw.intervalMs,
      gracePeriodMs: sw.gracePeriodMs,
      stages: sw.stages,
      reminders: sw.reminders || [],
      duress: sw.duress || null,
    };
    return createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
  }

  private freezeSwitchPlan(sw: SwitchConfig): { planHash: string; encryptedPlan: string } {
    const planHash = OboldEngine.computePlanHash(sw);
    const planSnapshot = {
      id: sw.id,
      name: sw.name,
      version: sw.version ?? 1,
      stages: sw.stages,
      reminders: sw.reminders || [],
      duress: sw.duress || null,
      planHash,
      frozenAt: Date.now(),
    };
    const aad = `plan:${sw.id}:v${sw.version ?? 1}`;
    const encryptedPlan = this.cipher.encryptToString(planSnapshot, aad);
    return { planHash, encryptedPlan };
  }

  private syncSwitchesWithDb(): void {
    const now = Date.now();
    for (const sw of this.config.switches) {
      const existing = this.db.getSwitch(sw.id);
      const { planHash, encryptedPlan } = this.freezeSwitchPlan(sw);

      if (!existing) {
        const nextDeadline = now + sw.intervalMs;
        const initialStatus = sw.enabled ? 'ARMED' : 'DISARMED';
        this.db.upsertSwitch(sw.id, sw.name, initialStatus, now, nextDeadline, -1, null, planHash, encryptedPlan);
      } else {
        if (!existing.plan_hash || !existing.frozen_plan || (existing.status === 'ARMED' && existing.active_stage_index === -1)) {
          this.db.upsertSwitch(
            sw.id,
            sw.name,
            existing.status,
            existing.last_checkin_at,
            existing.next_deadline_at,
            existing.active_stage_index,
            existing.stage_triggered_at,
            planHash,
            encryptedPlan
          );
        }
      }
    }
  }

  public getMonotonicElapsedMs(): number {
    return Number((process.hrtime.bigint() - this.monotonicStart) / 1_000_000n);
  }

  private classifyError(err: any, result?: ExecutionResult): DeliveryErrorType {
    const errorStr = (
      (err?.message || '') +
      ' ' +
      (result?.error || '') +
      ' ' +
      (result?.rawResponse || '')
    ).toLowerCase();

    const permanentPatterns = [
      'invalid credentials',
      'unauthorized',
      'forbidden',
      '401',
      '403',
      'invalid token',
      'chat not found',
      'user not found',
      'account suspended',
      'invalid url',
      'no such host',
      'syntax error',
      'blocked localhost',
      'blocked private',
    ];

    for (const pattern of permanentPatterns) {
      if (errorStr.includes(pattern)) {
        return 'PERMANENT';
      }
    }

    const transientPatterns = [
      'timeout',
      'econnreset',
      'econnrefused',
      'etimedout',
      'ehostunreach',
      'enotfound',
      'socket hang up',
      'network error',
      'rate limit',
      '429',
      '502',
      '503',
      '504',
      'temporarily unavailable',
    ];

    for (const pattern of transientPatterns) {
      if (errorStr.includes(pattern)) {
        return 'TRANSIENT';
      }
    }

    return 'UNKNOWN';
  }

  public async start(): Promise<void> {
    if (this.tickInterval) return;

    this.db.logAudit('INFO', 'ENGINE_START', 'obold dead man switch engine started.');
    this.emit('started');

    await this.replayLedger();

    this.lastTickTime = Date.now();
    this.lastMonotonicTick = process.hrtime.bigint();
    this.tickInterval = setInterval(() => {
      this.tick().catch((err) => {
        this.db.logAudit('ERROR', 'TICK_ERROR', `Unhandled engine tick error: ${err.message}`);
      });
    }, 1000);
  }

  public stop(): void {
    if (this.tickInterval) {
      clearInterval(this.tickInterval);
      this.tickInterval = null;
      this.db.logAudit('INFO', 'ENGINE_STOP', 'obold dead man switch engine stopped.');
      this.emit('stopped');
    }
  }

  public async replayLedger(): Promise<void> {
    const entries = this.ledger.getRecoverableEntries();
    if (entries.length === 0) return;

    this.db.logAudit('INFO', 'LEDGER_RECOVERY', `Found ${entries.length} recoverable ledger entries on startup.`);

    for (const entry of entries) {
      const sw = this.config.switches.find((s) => s.id === entry.switchId);
      const plugin = this.plugins.get(entry.plugin);

      if (!plugin) {
        this.ledger.markBlockedMissingPlugin(entry.id, entry.plugin);
        this.db.updateSwitchStatus(entry.switchId, 'BLOCKED');
        continue;
      }

      const payload = this.ledger.getDecryptedPayload(entry);
      this.ledger.claimEntry(entry.id);
      this.ledger.markExecuting(entry.id);

      try {
        const result = await plugin.execute(payload, {
          switchId: entry.switchId,
          switchName: sw?.name || entry.switchId,
          stageId: entry.stageId,
          actionId: entry.actionId,
          idempotencyKey: entry.idempotencyKey || entry.id,
          deadlineAt: Date.now(),
        });

        if (result.success) {
          this.ledger.markSucceeded(entry.id, result);
        } else {
          const failureType = this.classifyError(null, result);
          const nextRetry =
            failureType === 'PERMANENT' ? null : this.retryQueue.calculateNextRetry(entry.attemptCount + 1, entry.createdAt);
          this.ledger.markFailed(entry.id, result.error || 'Plugin returned failure', failureType, nextRetry);
        }
      } catch (err: any) {
        const failureType = this.classifyError(err);
        const nextRetry =
          failureType === 'PERMANENT' ? null : this.retryQueue.calculateNextRetry(entry.attemptCount + 1, entry.createdAt);
        this.ledger.markFailed(entry.id, err.message, failureType, nextRetry);
      }
    }
  }

  private async processSwitchTick(sw: SwitchConfig, now: number): Promise<void> {
    if (this.activeSwitchTicks.has(sw.id)) return;
    this.activeSwitchTicks.add(sw.id);

    try {
      if (!sw.enabled) return;
      const dbSw = this.db.getSwitch(sw.id);
      if (!dbSw) return;

      const nextDeadline = dbSw.next_deadline_at;
      const status = dbSw.status;

      if (status === 'ABORTED' || status === 'BLOCKED' || status === 'COMPLETED') {
        return;
      }

      if (status === 'PAUSED') {
        if (dbSw.paused_until && now >= dbSw.paused_until) {
          const remaining = Math.max(60000, dbSw.next_deadline_at - dbSw.last_checkin_at);
          const newDeadline = now + remaining;
          this.db.resumeSwitch(sw.id, newDeadline);
          this.db.logAudit('INFO', 'SWITCH_AUTO_RESUMED', `Switch ${sw.id} auto-resumed from vacation pause.`, undefined, sw.id);
          this.emit('switch:resumed', { switchId: sw.id, auto: true });
        }
        return;
      }

      if (status === 'ARMED') {
        this.evaluateReminders(sw, nextDeadline, now).catch((err: any) => {
          this.db.logAudit('ERROR', 'REMINDER_EVAL_ERROR', `Error evaluating reminders for switch ${sw.id}: ${err?.message || err}`, undefined, sw.id);
        });

        if (now >= nextDeadline) {
          const graceExpiresAt = nextDeadline + sw.gracePeriodMs;
          if (now >= graceExpiresAt) {
            await this.triggerSwitch(sw.id, false);
          } else {
            this.db.updateSwitchStatus(sw.id, 'GRACE_PERIOD');
            this.db.logAudit(
              'WARN',
              'GRACE_PERIOD',
              `Switch ${sw.id} deadline passed. Entered ${Math.round(sw.gracePeriodMs / 1000)}s grace period.`,
              undefined,
              sw.id
            );
            this.emit('switch:grace_period', { switchId: sw.id });
          }
        }
      } else if (status === 'GRACE_PERIOD') {
        const graceExpiresAt = nextDeadline + sw.gracePeriodMs;
        if (now >= graceExpiresAt) {
          await this.triggerSwitch(sw.id, false);
        }
      } else if (status === 'TRIGGERED' || status === 'TRIGGERING') {
        await this.evaluateCascade(sw, dbSw);
      }
    } catch (err: any) {
      this.db.logAudit('ERROR', 'SWITCH_TICK_ERROR', `Error processing switch ${sw.id} tick: ${err?.message || err}`, undefined, sw.id);
    } finally {
      this.activeSwitchTicks.delete(sw.id);
    }
  }

  private async tick(): Promise<void> {
    const now = Date.now();
    const monotonicNow = process.hrtime.bigint();
    const monotonicDeltaMs = Number((monotonicNow - this.lastMonotonicTick) / 1_000_000n);
    const timeDelta = now - this.lastTickTime;

    if (timeDelta > 10000 || Math.abs(timeDelta - monotonicDeltaMs) > 5000) {
      this.db.logAudit(
        'WARN',
        'TIME_JUMP',
        `Detected system clock shift: WallDelta=${Math.round(timeDelta / 1000)}s, MonotonicDelta=${Math.round(
          monotonicDeltaMs / 1000
        )}s (likely host wake or NTP adjustment).`
      );
    }
    this.lastTickTime = now;
    this.lastMonotonicTick = monotonicNow;

    const switchPromises = this.config.switches.map((sw) => this.processSwitchTick(sw, now));
    await Promise.allSettled(switchPromises);

    if (!this.isProcessingRetries) {
      this.isProcessingRetries = true;
      this.processRetries()
        .catch((err: any) => {
          this.db.logAudit('ERROR', 'RETRY_QUEUE_ERROR', `Error processing retry queue: ${err?.message || err}`);
        })
        .finally(() => {
          this.isProcessingRetries = false;
        });
    }

    this.emit('tick', { timestamp: now, monotonicMs: this.getMonotonicElapsedMs() });
  }

  private async executeWithTimeout<T>(
    fn: (signal: AbortSignal) => Promise<T>,
    timeoutMs: number,
    label: string,
    switchId?: string
  ): Promise<T> {
    const controller = new AbortController();
    if (switchId) {
      if (!this.activeControllers.has(switchId)) {
        this.activeControllers.set(switchId, new Set<AbortController>());
      }
      this.activeControllers.get(switchId)!.add(controller);
    }

    let timer: any;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        try {
          controller.abort(new Error(`Execution timed out after ${timeoutMs}ms for ${label}`));
        } catch {}
        reject(new Error(`Execution timed out after ${timeoutMs}ms for ${label}`));
      }, timeoutMs);
    });

    try {
      const executionPromise = fn(controller.signal);
      return await Promise.race([executionPromise, timeoutPromise]);
    } catch (err: any) {
      try {
        controller.abort(err);
      } catch {}
      throw err;
    } finally {
      clearTimeout(timer);
      if (switchId && this.activeControllers.has(switchId)) {
        this.activeControllers.get(switchId)!.delete(controller);
      }
    }
  }

  private async evaluateReminders(sw: SwitchConfig, nextDeadline: number, now: number): Promise<void> {
    if (!sw.reminders || sw.reminders.length === 0) return;

    if (!this.sentReminders.has(sw.id)) {
      this.sentReminders.set(sw.id, new Set<string>());
    }
    const sentSet = this.sentReminders.get(sw.id)!;

    for (const rem of sw.reminders) {
      const cycleKey = `reminder:${sw.id}:${rem.id}:${nextDeadline}`;
      const metaStatus = this.db.getMetadata(cycleKey);
      if (sentSet.has(rem.id) || metaStatus === 'SENT' || metaStatus === 'IN_FLIGHT') {
        if (metaStatus === 'SENT') {
          sentSet.add(rem.id);
        }
        continue;
      }

      const triggerThreshold = nextDeadline - rem.beforeMs;
      if (now >= triggerThreshold) {
        this.db.setMetadata(cycleKey, 'IN_FLIGHT');

        const plugin = this.plugins.get(rem.plugin);
        if (!plugin) {
          this.db.setMetadata(cycleKey, 'BLOCKED');
          this.db.logAudit(
            'ERROR',
            'PLUGIN_NOT_FOUND',
            `Reminder "${rem.name || rem.id}" requires plugin ${rem.plugin} which is not registered.`,
            undefined,
            sw.id
          );
          continue;
        }

        const entry = this.ledger.createEntry(sw.id, 'reminder', rem.id, rem.plugin, rem.config);
        this.ledger.claimEntry(entry.id);
        this.ledger.markExecuting(entry.id);

        try {
          const result = await this.executeWithTimeout(
            (signal) =>
              plugin.execute(rem.config, {
                switchId: sw.id,
                switchName: sw.name,
                stageId: 'reminder',
                actionId: rem.id,
                idempotencyKey: entry.idempotencyKey || entry.id,
                deadlineAt: nextDeadline,
                signal,
              }),
            15000,
            `reminder:${rem.id}`,
            sw.id
          );

          if (result.success) {
            sentSet.add(rem.id);
            this.db.setMetadata(cycleKey, 'SENT');
            this.ledger.markSucceeded(entry.id, result);
            this.db.logAudit(
              'INFO',
              'REMINDER_SENT',
              `Sent warning reminder "${rem.name || rem.id}" for switch ${sw.id}.`,
              undefined,
              sw.id
            );
            this.emit('switch:reminder', { switchId: sw.id, reminderId: rem.id });
          } else {
            this.db.setMetadata(cycleKey, 'FAILED');
            const failureType = this.classifyError(null, result);
            const nextRetry =
              failureType === 'PERMANENT' ? null : this.retryQueue.calculateNextRetry(1, entry.createdAt);
            this.ledger.markFailed(entry.id, result.error || 'Execution failed', failureType, nextRetry);
            this.db.logAudit(
              'ERROR',
              'REMINDER_FAIL',
              `Failed to send reminder ${rem.id}: ${result.error || 'Execution failed'}`,
              { switchId: sw.id },
              sw.id
            );
          }
        } catch (err: any) {
          this.db.setMetadata(cycleKey, 'FAILED');
          const failureType = this.classifyError(err);
          const nextRetry =
            failureType === 'PERMANENT' ? null : this.retryQueue.calculateNextRetry(1, entry.createdAt);
          this.ledger.markFailed(entry.id, err.message, failureType, nextRetry);
          this.db.logAudit('ERROR', 'REMINDER_FAIL', `Failed to send reminder ${rem.id}: ${err.message}`, { switchId: sw.id }, sw.id);
        }
      }
    }
  }

  public async triggerSwitch(
    switchId: string,
    dryRun: boolean = false,
    forceReplay: boolean = false,
    confirmDestructive: boolean = false
  ): Promise<{ alreadyTriggered?: boolean; status: string; executionId?: string; switchId?: string; triggeredAt?: number; results?: ExecutionResult[] }> {
    const sw = this.config.switches.find((s) => s.id === switchId);
    if (!sw) throw new Error(`Switch not found: ${switchId}`);

    const hasDestructive = sw.stages.some((st) => st.actions.some((a) => a.destructive === true));
    if (forceReplay && hasDestructive && !confirmDestructive) {
      throw new Error(
        `Switch "${switchId}" contains destructive actions. Force replay requires explicit confirmation (--confirm-destructive / confirmDestructive: true).`
      );
    }

    const dbSw = this.db.getSwitch(switchId);
    if (dbSw && (dbSw.status === 'TRIGGERED' || dbSw.status === 'TRIGGERING' || dbSw.status === 'COMPLETED') && !forceReplay) {
      this.db.logAudit(
        'WARN',
        'SWITCH_ALREADY_TRIGGERED',
        `Switch ${switchId} is already in ${dbSw.status} state. Manual trigger ignored (idempotent). Pass forceReplay=true to deliberately re-execute.`,
        { status: dbSw.status },
        switchId
      );
      return { alreadyTriggered: true, status: dbSw.status, switchId };
    }

    const now = Date.now();
    const executionId = `run-${sw.id}-${now}-${randomUUID().substring(0, 8)}`;
    this.db.updateSwitchStatus(switchId, 'TRIGGERING', 0, now);
    this.db.logAudit('FATAL', 'SWITCH_TRIGGERED', `Dead man switch ${switchId} (${sw.name}) has TRIGGERED! Execution ID: ${executionId}`, { executionId, dryRun, forceReplay }, switchId);
    this.emit('switch:triggered', { executionId, switchId, dryRun, forceReplay, triggeredAt: now });

    let results: ExecutionResult[] = [];
    if (sw.stages.length > 0) {
      results = await this.executeStage(sw, 0, dryRun, forceReplay);
      const postDbSw = this.db.getSwitch(switchId);
      if (postDbSw && postDbSw.status !== 'ABORTED' && postDbSw.status !== 'BLOCKED') {
        if (sw.stages.length === 1) {
          this.db.updateSwitchStatus(switchId, 'COMPLETED', 0, now);
        } else {
          this.db.updateSwitchStatus(switchId, 'TRIGGERED', 0, now);
        }
      }
    } else {
      this.db.updateSwitchStatus(switchId, 'COMPLETED', -1, now);
    }

    const finalDbSw = this.db.getSwitch(switchId);
    const finalStatus = finalDbSw ? finalDbSw.status : 'COMPLETED';

    return { alreadyTriggered: false, status: finalStatus, executionId, switchId, triggeredAt: now, results };
  }

  private async evaluateCascade(sw: SwitchConfig, dbSw: SwitchRow): Promise<void> {
    if (dbSw.status === 'ABORTED' || dbSw.status === 'COMPLETED' || dbSw.status === 'BLOCKED') {
      return;
    }

    const activeStageIndex = dbSw.active_stage_index;
    const nextStageIndex = activeStageIndex + 1;

    if (nextStageIndex >= sw.stages.length) {
      this.db.updateSwitchStatus(sw.id, 'COMPLETED', activeStageIndex, dbSw.stage_triggered_at);
      return;
    }

    const nextStage = sw.stages[nextStageIndex];
    const triggerBaseline = dbSw.stage_triggered_at || dbSw.updated_at || dbSw.next_deadline_at + sw.gracePeriodMs;
    const stageTriggerTime = triggerBaseline + nextStage.delayMs;

    if (Date.now() >= stageTriggerTime) {
      const now = Date.now();
      this.db.updateSwitchStatus(sw.id, 'TRIGGERED', nextStageIndex, now);
      await this.executeStage(sw, nextStageIndex, false, false);
    }
  }

  public async executeStage(sw: SwitchConfig, stageIndex: number, dryRun: boolean, isReplay: boolean = false): Promise<ExecutionResult[]> {
    let stage = sw.stages[stageIndex];
    const dbSw = this.db.getSwitch(sw.id);
    if (dbSw && dbSw.status === 'ABORTED') {
      return [];
    }

    if (dbSw && dbSw.frozen_plan && dbSw.plan_hash) {
      const currentPlanHash = OboldEngine.computePlanHash(sw);
      if (currentPlanHash !== dbSw.plan_hash) {
        this.db.logAudit(
          'WARN',
          'PLAN_HASH_MISMATCH',
          `Switch ${sw.id} memory config differs from frozen armed plan. Executing immutable frozen plan.`,
          { expectedHash: dbSw.plan_hash, currentHash: currentPlanHash },
          sw.id
        );
        try {
          const aad = `plan:${sw.id}:v${sw.version ?? 1}`;
          const decryptedPlan = JSON.parse(this.cipher.decryptFromString(dbSw.frozen_plan, aad));
          if (decryptedPlan && decryptedPlan.stages && decryptedPlan.stages[stageIndex]) {
            stage = decryptedPlan.stages[stageIndex];
          }
        } catch (err: any) {
          this.db.logAudit(
            'ERROR',
            'FROZEN_PLAN_DECRYPT_FAIL',
            `Failed to decrypt frozen execution plan for switch ${sw.id}: ${err.message}`,
            undefined,
            sw.id
          );
        }
      }
    }

    if (!stage) return [];

    const deadlineTimestamp = dbSw ? dbSw.next_deadline_at : Date.now();

    this.db.logAudit('INFO', 'STAGE_EXEC', `Executing Stage ${stageIndex + 1}: "${stage.name}" for switch ${sw.id}.`, undefined, sw.id);
    const results: ExecutionResult[] = [];

    for (const action of stage.actions) {
      const checkStatus = this.db.getSwitch(sw.id);
      if (checkStatus && checkStatus.status === 'ABORTED') {
        break;
      }
      const idempotencyKey = isReplay
        ? `idemp-${sw.id}-${stage.id}-${action.id}-replay-${Date.now()}`
        : `idemp-${sw.id}-${stage.id}-${action.id}-${randomUUID()}`;

      const plugin = this.plugins.get(action.plugin);
      const switchVersion = sw.version ?? 1;
      const pluginVersion = plugin ? plugin.version : '1.0.0';
      const pluginDigest = this.plugins.getPluginDigest(action.plugin);

      const contract: ExecutionContract = {
        switchId: sw.id,
        switchVersion,
        stageId: stage.id,
        actionId: action.id,
        plugin: action.plugin,
        pluginVersion,
        pluginDigest,
        configSnapshot: action.config,
        idempotencyKey,
        destructive: action.destructive === true,
        privileged: action.privileged === true,
        createdAt: Date.now(),
        deadlineAt: deadlineTimestamp,
      };

      if (!plugin) {
        const entry = this.ledger.createEntry(sw.id, stage.id, action.id, action.plugin, contract.configSnapshot, 10, contract.idempotencyKey);
        this.ledger.markBlockedMissingPlugin(entry.id, action.plugin);
        this.db.updateSwitchStatus(sw.id, 'BLOCKED');
        results.push({
          success: false,
          actionId: action.id,
          plugin: action.plugin,
          durationMs: 0,
          error: `CRITICAL: Action ${action.id} blocked because plugin "${action.plugin}" is missing.`,
        });
        continue;
      }

      const entry = this.ledger.createEntry(sw.id, stage.id, action.id, action.plugin, contract.configSnapshot, 10, contract.idempotencyKey);
      this.ledger.claimEntry(entry.id);
      this.ledger.markExecuting(entry.id);

      try {
        const timeoutMs = (action as any).timeoutMs || 30000;
        const result = await this.executeWithTimeout(
          (signal) =>
            plugin.execute(contract.configSnapshot, {
              switchId: sw.id,
              switchName: sw.name,
              stageId: stage.id,
              actionId: action.id,
              idempotencyKey: contract.idempotencyKey,
              deadlineAt: deadlineTimestamp,
              destructive: contract.destructive,
              privileged: contract.privileged,
              dryRun,
              signal,
            }),
          timeoutMs,
          `stage:${stage.id}:action:${action.id}`,
          sw.id
        );

        results.push(result);

        if (result.success) {
          this.ledger.markSucceeded(entry.id, result);
        } else {
          const failureType = this.classifyError(null, result);
          const nextRetry =
            failureType === 'PERMANENT' ? null : this.retryQueue.calculateNextRetry(1, entry.createdAt);
          this.ledger.markFailed(entry.id, result.error || 'Execution failed', failureType, nextRetry);
        }
      } catch (err: any) {
        const failureType = this.classifyError(err);
        const nextRetry =
          failureType === 'PERMANENT' ? null : this.retryQueue.calculateNextRetry(1, entry.createdAt);
        this.ledger.markFailed(entry.id, err.message, failureType, nextRetry);
        results.push({
          success: false,
          actionId: action.id,
          plugin: action.plugin,
          durationMs: 0,
          error: err.message,
        });
      }
    }

    return results;
  }

  private async processRetries(): Promise<void> {
    const dueEntries = this.retryQueue.getDueRetries();
    for (const entry of dueEntries) {
      if (this.ledger.hasActiveLease(entry.id)) {
        continue;
      }

      const sw = this.config.switches.find((s) => s.id === entry.switchId);

      if (entry.stageId === 'reminder') {
        const dbSw = this.db.getSwitch(entry.switchId);
        if (dbSw && dbSw.status === 'ARMED') {
          const remConfig = sw?.reminders?.find((r) => r.id === entry.actionId);
          const threshold = dbSw.next_deadline_at - (remConfig?.beforeMs || 0);
          if (Date.now() < threshold) {
            this.ledger.markSucceeded(entry.id, {
              success: true,
              actionId: entry.actionId,
              plugin: entry.plugin,
              durationMs: 0,
              output: { status: 'obsolete', message: 'Switch check-in extended deadline' },
            });
            continue;
          }
        }
      }

      const plugin = this.plugins.get(entry.plugin);
      if (!plugin) {
        this.ledger.markBlockedMissingPlugin(entry.id, entry.plugin);
        this.db.updateSwitchStatus(entry.switchId, 'BLOCKED');
        continue;
      }

      const payload = this.ledger.getDecryptedPayload(entry);
      this.ledger.claimEntry(entry.id);
      this.ledger.markExecuting(entry.id);

      try {
        const result = await this.executeWithTimeout(
          (signal) =>
            plugin.execute(payload, {
              switchId: entry.switchId,
              switchName: sw?.name || entry.switchId,
              stageId: entry.stageId,
              actionId: entry.actionId,
              idempotencyKey: entry.idempotencyKey || entry.id,
              deadlineAt: Date.now(),
              signal,
            }),
          30000,
          `retry:${entry.id}`,
          entry.switchId
        );

        if (result.success) {
          this.ledger.markSucceeded(entry.id, result);
        } else {
          const failureType = this.classifyError(null, result);
          const nextRetry =
            failureType === 'PERMANENT'
              ? null
              : this.retryQueue.calculateNextRetry(entry.attemptCount + 1, entry.createdAt);
          this.ledger.markFailed(entry.id, result.error || 'Retry attempt failed', failureType, nextRetry);
        }
      } catch (err: any) {
        const failureType = this.classifyError(err);
        const nextRetry =
          failureType === 'PERMANENT'
            ? null
            : this.retryQueue.calculateNextRetry(entry.attemptCount + 1, entry.createdAt);
        this.ledger.markFailed(entry.id, err.message, failureType, nextRetry);
      }
    }
  }

  public async checkin(switchId: string, isDuress: boolean = false): Promise<{ success: boolean; nextDeadlineAt: number }> {
    const sw = this.config.switches.find((s) => s.id === switchId);
    if (!sw) throw new Error(`Switch not found: ${switchId}`);

    const dbSw = this.db.getSwitch(switchId);
    if (dbSw) {
      const forbiddenStates = ['TRIGGERING', 'TRIGGERED', 'COMPLETED', 'ABORTED'];
      if (forbiddenStates.includes(dbSw.status)) {
        throw new Error(
          `Cannot check in to switch "${switchId}" because it is currently in "${dbSw.status}" state. An explicit reactivate/resume command is required.`
        );
      }
    }

    const now = Date.now();
    const nextDeadlineAt = now + sw.intervalMs;
    const { planHash, encryptedPlan } = this.freezeSwitchPlan(sw);

    this.db.upsertSwitch(sw.id, sw.name, 'ARMED', now, nextDeadlineAt, -1, null, planHash, encryptedPlan);

    if (this.sentReminders.has(switchId)) {
      this.sentReminders.get(switchId)!.clear();
    }

    if (isDuress) {
      this.db.logAudit(
        'FATAL',
        'DURESS_CHECKIN',
        `DURESS Check-in received for switch ${switchId}! Silent distress protocol engaged.`,
        undefined,
        switchId
      );
      this.emit('switch:duress', { switchId });

      if (sw.duress && sw.duress.enabled && sw.duress.actions) {
        for (const act of sw.duress.actions) {
          const idempotencyKey = `idemp-duress-${sw.id}-${act.id}-${randomUUID()}`;
          const contract: ExecutionContract = {
            switchId: sw.id,
            switchVersion: 1,
            stageId: 'duress',
            actionId: act.id,
            plugin: act.plugin,
            pluginVersion: '1.0.0',
            configSnapshot: act.config,
            idempotencyKey,
            destructive: false,
            privileged: false,
            createdAt: now,
            deadlineAt: nextDeadlineAt,
          };

          const entry = this.ledger.createEntry(sw.id, 'duress', act.id, act.plugin, act.config, 10, idempotencyKey);
          this.ledger.claimEntry(entry.id);
          this.ledger.markExecuting(entry.id);

          const plugin = this.plugins.get(act.plugin);
          if (!plugin) {
            this.ledger.markBlockedMissingPlugin(entry.id, act.plugin);
            this.db.logAudit(
              'ERROR',
              'PLUGIN_NOT_FOUND',
              `Duress action ${act.id} requires plugin "${act.plugin}" which is not registered.`,
              undefined,
              sw.id
            );
            continue;
          }

          try {
            const result = await this.executeWithTimeout(
              (signal) =>
                plugin.execute(act.config, {
                  switchId: sw.id,
                  switchName: sw.name,
                  stageId: 'duress',
                  actionId: act.id,
                  idempotencyKey,
                  deadlineAt: nextDeadlineAt,
                  isDuress: true,
                  signal,
                }),
              15000,
              `duress:${act.id}`,
              sw.id
            );

            if (result.success) {
              this.ledger.markSucceeded(entry.id, result);
              this.db.logAudit(
                'INFO',
                'DURESS_DISPATCHED',
                `Duress beacon action "${act.id}" (${act.plugin}) dispatched successfully.`,
                undefined,
                sw.id
              );
            } else {
              const failureType = this.classifyError(null, result);
              const nextRetry =
                failureType === 'PERMANENT'
                  ? null
                  : this.retryQueue.calculateNextRetry(1, entry.createdAt);
              this.ledger.markFailed(entry.id, result.error || 'Execution failed', failureType, nextRetry);
              this.db.logAudit(
                'ERROR',
                'DURESS_FAIL',
                `Duress action ${act.id} (${act.plugin}) failed: ${result.error || 'Execution failed'}`,
                { switchId: sw.id, actionId: act.id, error: result.error },
                sw.id
              );
            }
          } catch (err: any) {
            const failureType = this.classifyError(err);
            const nextRetry =
              failureType === 'PERMANENT'
                ? null
                : this.retryQueue.calculateNextRetry(1, entry.createdAt);
            this.ledger.markFailed(entry.id, err.message, failureType, nextRetry);
            this.db.logAudit(
              'ERROR',
              'DURESS_FAIL',
              `Duress action ${act.id} (${act.plugin}) threw exception: ${err?.message || err}`,
              { switchId: sw.id, actionId: act.id, error: String(err?.message || err) },
              sw.id
            );
          }
        }
      }
    } else {
      this.db.logAudit(
        'INFO',
        'CHECKIN',
        `Check-in received for switch ${switchId}. Timer extended to ${new Date(nextDeadlineAt).toISOString()}.`,
        undefined,
        switchId
      );
      this.emit('switch:checkin', { switchId, nextDeadlineAt });
    }

    return { success: true, nextDeadlineAt };
  }

  public async checkinWithToken(tokenHash: string, switchId: string, isDuress: boolean = false): Promise<{ success: boolean; nextDeadlineAt: number }> {
    const sw = this.config.switches.find((s) => s.id === switchId);
    if (!sw) throw new Error(`Switch not found: ${switchId}`);

    const dbSw = this.db.getSwitch(switchId);
    if (dbSw) {
      const forbiddenStates = ['TRIGGERING', 'TRIGGERED', 'COMPLETED', 'ABORTED'];
      if (forbiddenStates.includes(dbSw.status)) {
        throw new Error(
          `Cannot check in to switch "${switchId}" because it is currently in "${dbSw.status}" state. An explicit reactivate/resume command is required.`
        );
      }
    }

    const { planHash, encryptedPlan } = this.freezeSwitchPlan(sw);
    const result = this.db.atomicCheckinWithToken(tokenHash, switchId, sw.name, sw.intervalMs, planHash, encryptedPlan);
    const effectiveDuress = isDuress || result.isDuress;

    if (this.sentReminders.has(switchId)) {
      this.sentReminders.get(switchId)!.clear();
    }

    if (effectiveDuress) {
      this.db.logAudit(
        'FATAL',
        'DURESS_CHECKIN',
        `DURESS Check-in received for switch ${switchId}! Silent distress protocol engaged.`,
        undefined,
        switchId
      );
      this.emit('switch:duress', { switchId });

      if (sw.duress && sw.duress.enabled && sw.duress.actions) {
        for (const act of sw.duress.actions) {
          const idempotencyKey = `idemp-duress-${sw.id}-${act.id}-${randomUUID()}`;
          const contract: ExecutionContract = {
            switchId: sw.id,
            switchVersion: 1,
            stageId: 'duress',
            actionId: act.id,
            plugin: act.plugin,
            pluginVersion: '1.0.0',
            configSnapshot: act.config,
            idempotencyKey,
            destructive: false,
            privileged: false,
            createdAt: Date.now(),
            deadlineAt: result.nextDeadlineAt,
          };

          const entry = this.ledger.createEntry(sw.id, 'duress', act.id, act.plugin, act.config, 10, idempotencyKey);
          this.ledger.claimEntry(entry.id);
          this.ledger.markExecuting(entry.id);

          const plugin = this.plugins.get(act.plugin);
          if (!plugin) {
            this.ledger.markBlockedMissingPlugin(entry.id, act.plugin);
            continue;
          }

          try {
            const res = await this.executeWithTimeout(
              (signal) =>
                plugin.execute(act.config, {
                  switchId: sw.id,
                  switchName: sw.name,
                  stageId: 'duress',
                  actionId: act.id,
                  idempotencyKey,
                  deadlineAt: result.nextDeadlineAt,
                  isDuress: true,
                  signal,
                }),
              15000,
              `duress:${act.id}`,
              sw.id
            );

            if (res.success) {
              this.ledger.markSucceeded(entry.id, res);
            } else {
              this.ledger.markFailed(entry.id, res.error || 'Duress action failed', 'TRANSIENT');
            }
          } catch (err: any) {
            this.ledger.markFailed(entry.id, err.message, 'TRANSIENT');
          }
        }
      }
    } else {
      this.db.logAudit(
        'INFO',
        'CHECKIN',
        `Check-in received for switch ${switchId}. Timer extended to ${new Date(result.nextDeadlineAt).toISOString()}.`,
        undefined,
        switchId
      );
      this.emit('switch:checkin', { switchId, nextDeadlineAt: result.nextDeadlineAt });
    }

    return { success: true, nextDeadlineAt: result.nextDeadlineAt };
  }

  public abortSwitch(switchId: string, reason?: string): boolean {
    const sw = this.config.switches.find((s) => s.id === switchId);
    if (!sw) return false;

    if (this.activeControllers.has(switchId)) {
      const controllers = this.activeControllers.get(switchId)!;
      for (const ctrl of controllers) {
        try {
          ctrl.abort(new Error(`Switch execution aborted by operator: ${reason || 'Manual abort'}`));
        } catch {}
      }
      controllers.clear();
    }

    const abortedEntriesCount = this.db.abortLedgerEntriesForSwitch(switchId, reason || 'Operator manual abort');
    this.db.updateSwitchStatus(switchId, 'ABORTED');
    this.db.logAudit(
      'FATAL',
      'EMERGENCY_ABORT',
      `EMERGENCY ABORT: Switch ${switchId} cascade aborted by operator. In-flight tasks terminated (${abortedEntriesCount} ledger entries purged/aborted). Reason: ${reason || 'Operator manual abort'}.`,
      { switchId, reason, abortedEntriesCount },
      switchId
    );
    this.emit('switch:aborted', { switchId, reason, abortedEntriesCount });
    return true;
  }

  public pauseSwitch(switchId: string, durationMs?: number, reason?: string): boolean {
    const sw = this.config.switches.find((s) => s.id === switchId);
    if (!sw) return false;
    const pausedUntil = durationMs ? Date.now() + durationMs : null;
    const ok = this.db.pauseSwitch(switchId, pausedUntil, reason);
    if (ok) {
      this.emit('switch:paused', { switchId, pausedUntil, reason });
    }
    return ok;
  }

  public resumeSwitch(switchId: string): boolean {
    const sw = this.config.switches.find((s) => s.id === switchId);
    if (!sw) return false;
    const ok = this.db.resumeSwitch(switchId);
    if (ok) {
      this.emit('switch:resumed', { switchId, auto: false });
    }
    return ok;
  }

  public getRuntimeStates(): SwitchRuntimeState[] {
    const now = Date.now();
    const recoverable = this.ledger.getRecoverableEntries();
    const retryCounts = new Map<string, number>();
    for (const entry of recoverable) {
      retryCounts.set(entry.switchId, (retryCounts.get(entry.switchId) || 0) + 1);
    }

    return this.config.switches.map((sw) => {
      const dbSw = this.db.getSwitch(sw.id);
      const nextDeadlineAt = dbSw ? dbSw.next_deadline_at : now + sw.intervalMs;
      const lastCheckinAt = dbSw ? dbSw.last_checkin_at : now;
      const status = dbSw ? dbSw.status : sw.enabled ? 'ARMED' : 'DISARMED';
      const activeStageIndex = dbSw ? dbSw.active_stage_index : -1;
      const stageTriggeredAt = dbSw ? dbSw.stage_triggered_at : null;
      const remainingMs = Math.max(0, nextDeadlineAt - now);

      return {
        id: sw.id,
        name: sw.name,
        status,
        lastCheckinAt,
        nextDeadlineAt,
        remainingMs,
        activeStageIndex,
        stageTriggeredAt,
        stagesTotal: sw.stages.length,
        pendingRetries: retryCounts.get(sw.id) || 0,
        pausedUntil: dbSw ? dbSw.paused_until : null,
        pauseReason: dbSw ? dbSw.pause_reason : null,
      };
    });
  }

  public getDb(): OboldDatabase {
    return this.db;
  }
}
