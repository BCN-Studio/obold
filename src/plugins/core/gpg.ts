import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import type { IPluginExecutor, PluginExecutionContext } from '../types.ts';
import type { ExecutionResult } from '../../config/types.ts';

export class GpgPlugin implements IPluginExecutor {
  readonly id = 'core:gpg';
  readonly name = 'GPG File Cryptor';
  readonly description = 'Encrypts or decrypts local sensitive files with GPG keys upon trigger.';
  readonly version = '1.0.0';

  validateConfig(config: Record<string, any>): { valid: boolean; error?: string } {
    if (!config.input_path) return { valid: false, error: 'Missing required field: "input_path".' };
    if (!config.action || (config.action !== 'encrypt' && config.action !== 'decrypt')) {
      return { valid: false, error: 'Field "action" must be either "encrypt" or "decrypt".' };
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

    if (context.dryRun) {
      return {
        success: true,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        output: { dryRun: true, action: config.action, input: config.input_path, message: '[DRY-RUN GPG NOOP] Cryptographic transformation simulated and not written to disk' },
      };
    }

    if (context.signal && context.signal.aborted) {
      return {
        success: false,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        error: 'GPG execution cancelled by abort signal before process launch',
      };
    }

    const inputPath = config.input_path;
    const outputPath = config.output_path || `${inputPath}.${config.action === 'encrypt' ? 'gpg' : 'dec'}`;
    const action = config.action;

    if (!existsSync(inputPath)) {
      return {
        success: false,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        error: `Input file does not exist: ${inputPath}`,
      };
    }

    let proc: any;
    let abortHandler: (() => void) | null = null;

    try {
      const args: string[] = ['gpg', '--batch', '--yes'];

      if (action === 'encrypt') {
        if (config.recipient) {
          args.push('--encrypt', '--recipient', config.recipient);
        } else if (config.passphrase) {
          let pass = config.passphrase;
          if (pass.startsWith('ENV:')) pass = process.env[pass.substring(4)] || '';
          args.push('--symmetric', '--passphrase', pass);
        }
      } else {
        if (config.passphrase) {
          let pass = config.passphrase;
          if (pass.startsWith('ENV:')) pass = process.env[pass.substring(4)] || '';
          args.push('--decrypt', '--passphrase', pass);
        } else {
          args.push('--decrypt');
        }
      }

      args.push('--output', outputPath, inputPath);

      proc = Bun.spawn(args, {
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

      const outcome: any = await Promise.race([
        proc.exited.then((code: any) => ({ isAbort: false, exitCode: code })),
        abortPromise,
      ]);

      if (outcome && outcome.isAbort) {
        try {
          if (proc) proc.kill();
        } catch {}
        return {
          success: false,
          actionId: context.actionId,
          plugin: this.id,
          durationMs: Date.now() - startTime,
          error: 'GPG process terminated by abort signal',
        };
      }

      const exitCode = outcome.exitCode;
      const isSuccess = exitCode === 0;

      return {
        success: isSuccess,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        output: { action, inputPath, outputPath, exitCode },
        error: isSuccess ? undefined : `GPG exited with code ${exitCode}`,
      };
    } catch (err: any) {
      return {
        success: false,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        error: `GPG Execution Error: ${err.message}`,
      };
    } finally {
      if (context.signal && abortHandler) {
        context.signal.removeEventListener('abort', abortHandler);
      }
    }
  }
}
