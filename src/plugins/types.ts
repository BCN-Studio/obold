import type { ExecutionResult } from '../config/types.ts';

export type PluginRiskTier = 'TRUSTED_CORE' | 'SENSITIVE_CORE' | 'PRIVILEGED_HOST' | 'COMMUNITY';
export type ReplaySafety = 'SAFE' | 'IDEMPOTENT' | 'UNKNOWN' | 'FORBIDDEN';

export interface PluginExecutionContext {
  switchId: string;
  switchName: string;
  stageId?: string;
  actionId: string;
  idempotencyKey?: string;
  deadlineAt: number;
  isDuress?: boolean;
  dryRun?: boolean;
  destructive?: boolean;
  privileged?: boolean;
  masterKey?: Buffer;
  signal?: AbortSignal;
  capabilities?: string[];
}

export interface IPluginExecutor {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly version: string;
  readonly riskTier?: PluginRiskTier;
  readonly replaySafety?: ReplaySafety;
  readonly capabilities?: string[];

  validateConfig(config: Record<string, any>): { valid: boolean; error?: string };
  execute(config: Record<string, any>, context: PluginExecutionContext): Promise<ExecutionResult>;
}
