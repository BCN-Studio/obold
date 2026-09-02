export type LedgerState =
  | 'PENDING'
  | 'CLAIMED'
  | 'EXECUTING'
  | 'SUCCEEDED'
  | 'FAILED_RETRYABLE'
  | 'FAILED_PERMANENT'
  | 'BLOCKED_PLUGIN_MISSING'
  | 'BLOCKED'
  | 'UNKNOWN'
  | 'ARMED'
  | 'DISPATCHED'
  | 'ACKNOWLEDGED'
  | 'FAILED';

export type DeliveryErrorType = 'TRANSIENT' | 'PERMANENT' | 'UNKNOWN';

export type SwitchStatus =
  | 'ARMED'
  | 'DISARMED'
  | 'GRACE_PERIOD'
  | 'TRIGGERING'
  | 'TRIGGERED'
  | 'PARTIALLY_COMPLETED'
  | 'COMPLETED'
  | 'ABORTED'
  | 'BLOCKED'
  | 'PAUSED';

export type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'FATAL';

export interface ExecutionContract {
  switchId: string;
  switchVersion: number;
  stageId: string;
  actionId: string;
  plugin: string;
  pluginVersion?: string;
  pluginDigest?: string;
  configSnapshot: Record<string, any>;
  idempotencyKey: string;
  destructive?: boolean;
  privileged?: boolean;
  createdAt: number;
  deadlineAt: number;
}

export interface PluginActionConfig {
  id: string;
  plugin: string;
  name?: string;
  description?: string;
  config: Record<string, any>;
  timeoutMs?: number;
  continueOnError?: boolean;
  dependsOn?: string[];
  destructive?: boolean;
  privileged?: boolean;
}

export interface StageConfig {
  id: string;
  name: string;
  delayMs: number;
  description?: string;
  actions: PluginActionConfig[];
}

export interface ReminderConfig {
  id: string;
  beforeMs: number;
  name?: string;
  plugin: string;
  config: Record<string, any>;
}

export interface DuressConfig {
  enabled: boolean;
  pin?: string;
  actions: PluginActionConfig[];
}

export interface SwitchConfig {
  id: string;
  name: string;
  version?: number;
  description?: string;
  enabled: boolean;
  intervalMs: number;
  gracePeriodMs: number;
  reminders?: ReminderConfig[];
  stages: StageConfig[];
  duress?: DuressConfig;
  tags?: string[];
}

export type ApiRole = 'admin' | 'operator' | 'checkin' | 'read';

export interface ApiKeyConfig {
  token: string;
  roles: ApiRole[];
  name?: string;
}

export interface ServerConfig {
  enabled: boolean;
  host: string;
  port: number;
  apiAuthToken?: string;
  apiKeys?: ApiKeyConfig[];
  corsOrigins?: string[];
  trustedProxies?: string[];
  allowRemoteCryptoApi?: boolean;
  publicHealth?: boolean;
  publicCheckin?: boolean;
  publicMetrics?: boolean;
  publicEvents?: boolean;
}

export interface StorageConfig {
  path: string;
  walMode: boolean;
  autoCheckpointIntervalMs?: number;
}

export interface CryptoConfig {
  algorithm: 'chacha20-poly1305' | 'aes-256-gcm';
  keyDerivation: 'argon2id' | 'scrypt' | 'pbkdf2';
  salt?: string;
}

export interface OboldConfig {
  version: string;
  organization?: string;
  storage: StorageConfig;
  crypto: CryptoConfig;
  server: ServerConfig;
  switches: SwitchConfig[];
  logLevel?: LogLevel;
}

export interface LedgerRecord {
  id: string;
  switchId: string;
  stageId: string;
  actionId: string;
  plugin: string;
  state: LedgerState;
  idempotencyKey?: string | null;
  attemptCount: number;
  maxAttempts: number;
  nextRetryAt?: number | null;
  lastError?: string | null;
  payloadSnapshot?: string | null;
  resultSnapshot?: string | null;
  createdAt: number;
  updatedAt: number;
  dispatchedAt?: number | null;
  acknowledgedAt?: number | null;
}

export interface HeartbeatToken {
  id: string;
  switchId: string;
  tokenHash: string;
  expiresAt: number;
  usedAt?: number | null;
  isDuress?: boolean;
  createdAt: number;
}

export interface ExecutionResult {
  success: boolean;
  actionId: string;
  plugin: string;
  durationMs: number;
  idempotencyKey?: string;
  deliveryErrorType?: DeliveryErrorType;
  output?: any;
  error?: string;
  rawResponse?: string;
}

export interface SwitchRuntimeState {
  id: string;
  name: string;
  status: SwitchStatus;
  lastCheckinAt: number;
  nextDeadlineAt: number;
  remainingMs: number;
  activeStageIndex: number;
  stagesTotal: number;
  pendingRetries: number;
  stageTriggeredAt?: number | null;
  pausedUntil?: number | null;
  pauseReason?: string | null;
}

export interface SwitchRow {
  id: string;
  name: string;
  status: SwitchStatus;
  last_checkin_at: number;
  next_deadline_at: number;
  active_stage_index: number;
  stage_triggered_at: number | null;
  paused_until?: number | null;
  pause_reason?: string | null;
  plan_hash?: string | null;
  frozen_plan?: string | null;
  created_at: number;
  updated_at: number;
}

export interface AuditLogRow {
  id: string;
  level: LogLevel;
  category: string;
  switch_id: string | null;
  message: string;
  metadata: string | null;
  created_at: number;
}

export interface HeartbeatTokenRow {
  id: string;
  switch_id: string;
  token_hash: string;
  expires_at: number;
  used_at: number | null;
  is_duress: number;
  created_at: number;
}

export interface ExecutionLedgerRow {
  id: string;
  switch_id: string;
  stage_id: string;
  action_id: string;
  plugin: string;
  state: LedgerState;
  idempotency_key?: string | null;
  attempt_count: number;
  max_attempts: number;
  next_retry_at: number | null;
  last_error: string | null;
  payload_snapshot: string | null;
  result_snapshot: string | null;
  created_at: number;
  updated_at: number;
  dispatched_at: number | null;
  acknowledged_at: number | null;
}

export type { PluginExecutionContext, IPluginExecutor, PluginRiskTier } from '../plugins/types.ts';
