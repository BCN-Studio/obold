import type { IPluginExecutor, PluginExecutionContext } from '../types.ts';
import type { ExecutionResult } from '../../config/types.ts';

export class ExternalProcessPlugin implements IPluginExecutor {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly version: string;
  private binaryPath: string;

  constructor(id: string, name: string, binaryPath: string, description: string = 'Community Plugin', version: string = '1.0.0') {
    this.id = id;
    this.name = name;
    this.description = description;
    this.version = version;
    this.binaryPath = binaryPath;
  }

  validateConfig(config: Record<string, any>): { valid: boolean; error?: string } {
    return { valid: true };
  }

  async execute(config: Record<string, any>, context: PluginExecutionContext): Promise<ExecutionResult> {
    const startTime = Date.now();

    if (context.dryRun) {
      return {
        success: true,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        output: { dryRun: true, binaryPath: this.binaryPath, message: '[DRY-RUN PROCESS NOOP] External plugin process spawn intercepted' },
      };
    }

    if (context.signal && context.signal.aborted) {
      return {
        success: false,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        error: 'External plugin execution cancelled by abort signal before process launch',
      };
    }

    const payload = JSON.stringify({
      jsonrpc: '2.0',
      method: 'execute',
      params: { config, context },
    });

    let proc: any;
    let abortHandler: (() => void) | null = null;

    try {
      proc = Bun.spawn([this.binaryPath], {
        stdin: 'pipe',
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

      proc.stdin.write(payload + '\n');
      proc.stdin.flush();
      proc.stdin.end();

      const executionPromise = Promise.all([
        new Response(proc.stdout).text(),
        proc.exited,
      ]).then(([stdoutText, exitCode]) => ({
        isAbort: false,
        stdoutText,
        exitCode,
      }));

      const outcome: any = await Promise.race([executionPromise, abortPromise]);

      if (outcome && outcome.isAbort) {
        try {
          if (proc) proc.kill();
        } catch {}
        return {
          success: false,
          actionId: context.actionId,
          plugin: this.id,
          durationMs: Date.now() - startTime,
          error: 'External plugin process terminated by abort signal',
        };
      }

      const { stdoutText, exitCode } = outcome;

      if (exitCode !== 0) {
        return {
          success: false,
          actionId: context.actionId,
          plugin: this.id,
          durationMs: Date.now() - startTime,
          error: `External plugin exited with code ${exitCode}`,
        };
      }

      let parsed: any;
      try {
        parsed = JSON.parse(stdoutText.trim());
      } catch {
        return {
          success: true,
          actionId: context.actionId,
          plugin: this.id,
          durationMs: Date.now() - startTime,
          output: { rawOutput: stdoutText },
        };
      }

      return {
        success: parsed.success !== false,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        output: parsed.output || parsed,
        error: parsed.error,
      };
    } catch (err: any) {
      return {
        success: false,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        error: `Failed to execute external plugin [${this.binaryPath}]: ${err.message}`,
      };
    } finally {
      if (context.signal && abortHandler) {
        context.signal.removeEventListener('abort', abortHandler);
      }
    }
  }
}
