import type { IPluginExecutor, PluginExecutionContext, PluginRiskTier } from '../types.ts';
import type { ExecutionResult } from '../../config/types.ts';

export class ShellPlugin implements IPluginExecutor {
  readonly id = 'core:shell';
  readonly name = 'Host Shell Executor';
  readonly description = 'Executes local host scripts, Docker teardowns, or key-shredding operations.';
  readonly version = '1.0.0';
  readonly riskTier: PluginRiskTier = 'PRIVILEGED_HOST';

  validateConfig(config: Record<string, any>): { valid: boolean; error?: string } {
    if (!config.command && !config.script_path) {
      return { valid: false, error: 'Missing required field: "command" or "script_path".' };
    }
    return { valid: true };
  }

  async execute(config: Record<string, any>, context: PluginExecutionContext): Promise<ExecutionResult> {
    const startTime = Date.now();
    const validation = this.validateConfig(config);
    if (!validation.valid) {
      return {
        success: false,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: 0,
        error: validation.error,
      };
    }

    const commandStr = config.command || config.script_path;

    if (context.dryRun) {
      return {
        success: true,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        output: { dryRun: true, command: commandStr, message: '[DRY-RUN SHELL NOOP] Command intercepted and not executed' },
      };
    }

    if (context.signal && context.signal.aborted) {
      return {
        success: false,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        error: 'Execution cancelled by abort signal before process launch',
      };
    }

    const timeoutMs = config.timeout_ms || 30000;
    const isWindows = process.platform === 'win32';
    const shellCmd = isWindows ? ['cmd.exe', '/c', commandStr] : ['/bin/sh', '-c', commandStr];

    const env: Record<string, string> = {
      ...process.env,
      OBOLD_SWITCH_ID: context.switchId,
      OBOLD_SWITCH_NAME: context.switchName,
      OBOLD_STAGE_ID: context.stageId || '',
      OBOLD_ACTION_ID: context.actionId,
      OBOLD_IS_DURESS: context.isDuress ? '1' : '0',
      ...(config.env_vars || {}),
    };

    let proc: any;
    let abortHandler: (() => void) | null = null;

    try {
      proc = Bun.spawn(shellCmd, {
        cwd: config.cwd || process.cwd(),
        env,
        stdout: 'pipe',
        stderr: 'pipe',
      });

      let abortPromise = new Promise<{ isAbort: true }>((resolve) => {
        if (context.signal) {
          if (context.signal.aborted) {
            resolve({ isAbort: true });
          } else {
            abortHandler = () => {
              try {
                if (proc) proc.kill();
              } catch {}
              resolve({ isAbort: true });
            };
            context.signal.addEventListener('abort', abortHandler, { once: true });
          }
        }
      });

      let timeoutHandle: any;
      const timeoutPromise = new Promise<{ isTimeout: true }>((resolve) => {
        timeoutHandle = setTimeout(() => resolve({ isTimeout: true }), timeoutMs);
      });

      const executionPromise = Promise.all([
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
        proc.exited,
      ]).then(([stdout, stderr, exitCode]) => ({
        isTimeout: false,
        isAbort: false,
        stdout,
        stderr,
        exitCode,
      }));

      const outcome: any = await Promise.race([executionPromise, timeoutPromise, abortPromise]);
      clearTimeout(timeoutHandle);

      if (outcome && outcome.isAbort) {
        try {
          if (proc) proc.kill();
        } catch {}
        return {
          success: false,
          actionId: context.actionId,
          plugin: this.id,
          durationMs: Date.now() - startTime,
          error: 'Shell command terminated by abort signal',
        };
      }

      if (outcome && outcome.isTimeout) {
        try {
          if (proc) proc.kill();
        } catch {}
        return {
          success: false,
          actionId: context.actionId,
          plugin: this.id,
          durationMs: Date.now() - startTime,
          error: `Shell command timed out after ${timeoutMs}ms`,
        };
      }

      if (context.signal && context.signal.aborted) {
        try {
          if (proc) proc.kill();
        } catch {}
        return {
          success: false,
          actionId: context.actionId,
          plugin: this.id,
          durationMs: Date.now() - startTime,
          error: 'Shell command terminated by abort signal',
        };
      }

      const isSuccess = outcome.exitCode === 0;

      return {
        success: isSuccess,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        output: {
          exitCode: outcome.exitCode,
          stdout: outcome.stdout.substring(0, 4000),
          stderr: outcome.stderr.substring(0, 4000),
        },
        error: isSuccess ? undefined : `Process exited with non-zero code ${outcome.exitCode}: ${outcome.stderr.substring(0, 200)}`,
      };
    } catch (err: any) {
      if (proc) {
        try { proc.kill(); } catch {}
      }
      return {
        success: false,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        error: `Shell execution error: ${err.message}`,
      };
    } finally {
      if (context.signal && abortHandler) {
        context.signal.removeEventListener('abort', abortHandler);
      }
    }
  }
}
