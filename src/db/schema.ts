export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS switches (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ARMED',
  last_checkin_at INTEGER NOT NULL,
  next_deadline_at INTEGER NOT NULL,
  active_stage_index INTEGER NOT NULL DEFAULT -1,
  stage_triggered_at INTEGER DEFAULT NULL,
  paused_until INTEGER DEFAULT NULL,
  pause_reason TEXT DEFAULT NULL,
  plan_hash TEXT DEFAULT NULL,
  frozen_plan TEXT DEFAULT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS heartbeat_tokens (
  id TEXT PRIMARY KEY,
  switch_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  used_at INTEGER DEFAULT NULL,
  is_duress INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (switch_id) REFERENCES switches(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS execution_ledger (
  id TEXT PRIMARY KEY,
  switch_id TEXT NOT NULL,
  stage_id TEXT NOT NULL,
  action_id TEXT NOT NULL,
  plugin TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'PENDING',
  idempotency_key TEXT DEFAULT NULL,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 10,
  next_retry_at INTEGER DEFAULT NULL,
  last_error TEXT DEFAULT NULL,
  payload_snapshot TEXT DEFAULT NULL,
  result_snapshot TEXT DEFAULT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  dispatched_at INTEGER DEFAULT NULL,
  acknowledged_at INTEGER DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  level TEXT NOT NULL,
  category TEXT NOT NULL,
  switch_id TEXT DEFAULT NULL,
  message TEXT NOT NULL,
  metadata TEXT DEFAULT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS system_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_switches_deadline ON switches(next_deadline_at);
CREATE INDEX IF NOT EXISTS idx_tokens_hash ON heartbeat_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_tokens_expiry ON heartbeat_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_ledger_state ON execution_ledger(state);
CREATE INDEX IF NOT EXISTS idx_ledger_retry ON execution_ledger(next_retry_at);
CREATE INDEX IF NOT EXISTS idx_ledger_idempotency ON execution_ledger(idempotency_key);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(created_at DESC);
`;

