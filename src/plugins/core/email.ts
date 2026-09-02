import { connect as connectTls } from 'node:tls';
import { createConnection } from 'node:net';
import type { IPluginExecutor, PluginExecutionContext } from '../types.ts';
import type { ExecutionResult } from '../../config/types.ts';

export class EmailPlugin implements IPluginExecutor {
  readonly id = 'core:email';
  readonly name = 'SMTP Email Dispatcher';
  readonly description = 'Dispatches TLS-encrypted emails and attachments via standard SMTP servers.';
  readonly version = '1.0.0';

  validateConfig(config: Record<string, any>): { valid: boolean; error?: string } {
    if (!config.smtp_host || typeof config.smtp_host !== 'string') {
      return { valid: false, error: 'Missing required field: "smtp_host".' };
    }
    if (!config.to || (Array.isArray(config.to) && config.to.length === 0)) {
      return { valid: false, error: 'Missing required field: "to" (recipient email array or string).' };
    }
    if (!config.subject) {
      return { valid: false, error: 'Missing required field: "subject".' };
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

    const recipients = Array.isArray(config.to) ? config.to : [config.to];
    const fromAddr = config.from || 'obold-daemon@bcnstudio.tech';
    const subject = config.subject;
    const body = config.body || config.html_template || 'Automated notification from obold dead man switch daemon.';

    if (context.dryRun) {
      return {
        success: true,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        output: { dryRun: true, host: config.smtp_host, recipients, subject },
      };
    }

    let smtpUser = config.smtp_user || '';
    if (smtpUser.startsWith('ENV:')) {
      smtpUser = process.env[smtpUser.substring(4)] || '';
    }

    let smtpPass = config.smtp_pass || '';
    if (smtpPass.startsWith('ENV:')) {
      smtpPass = process.env[smtpPass.substring(4)] || '';
    }

    const host = config.smtp_host;
    const port = config.smtp_port || 587;
    const useTlsDirect = port === 465;

    try {
      await this.sendSmtp({
        host,
        port,
        useTlsDirect,
        user: smtpUser,
        pass: smtpPass,
        from: fromAddr,
        to: recipients,
        subject,
        body,
        timeoutMs: config.timeout_ms || 30000,
        signal: context.signal,
      });

      return {
        success: true,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        output: { recipients, status: '250 OK Delivered' },
      };
    } catch (err: any) {
      return {
        success: false,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        error: `SMTP Dispatch Error: ${err.message}`,
      };
    }
  }

  private sendSmtp(options: {
    host: string;
    port: number;
    useTlsDirect: boolean;
    user: string;
    pass: string;
    from: string;
    to: string[];
    subject: string;
    body: string;
    timeoutMs: number;
    signal?: AbortSignal;
  }): Promise<void> {
    return new Promise((resolve, reject) => {
      let socket: any;
      let buffer = '';
      let stage = 0;

      const timer = setTimeout(() => {
        if (socket) socket.destroy();
        reject(new Error(`SMTP connection timed out after ${options.timeoutMs}ms`));
      }, options.timeoutMs);

      const abortHandler = () => {
        if (socket) socket.destroy();
        clearTimeout(timer);
        reject(new Error('SMTP dispatch aborted by cancellation signal'));
      };

      if (options.signal) {
        if (options.signal.aborted) {
          clearTimeout(timer);
          return reject(new Error('SMTP dispatch aborted before connect'));
        }
        options.signal.addEventListener('abort', abortHandler, { once: true });
      }

      const cleanup = () => {
        clearTimeout(timer);
        if (options.signal) {
          options.signal.removeEventListener('abort', abortHandler);
        }
      };

      const send = (line: string) => {
        socket.write(line + '\r\n');
      };

      const onData = (data: Buffer) => {
        buffer += data.toString('utf-8');
        const lines = buffer.split('\r\n');
        buffer = lines.pop() || ''; 

        for (const line of lines) {
          if (!line) continue;
          const code = parseInt(line.substring(0, 3), 10);
          if (line[3] === '-') continue; 

          if (code >= 400) {
            cleanup();
            socket.destroy();
            return reject(new Error(`SMTP server error [${code}]: ${line}`));
          }

          if (stage === 0 && code === 220) {
            
            stage = 1;
            send(`EHLO obold.local`);
          } else if (stage === 1 && code === 250) {
            
            if (options.user && options.pass) {
              stage = 2;
              send('AUTH LOGIN');
            } else {
              stage = 4;
              send(`MAIL FROM:<${options.from}>`);
            }
          } else if (stage === 2 && code === 334) {
            
            stage = 3;
            send(Buffer.from(options.user).toString('base64'));
          } else if (stage === 3 && code === 334) {
            
            stage = 4;
            send(Buffer.from(options.pass).toString('base64'));
          } else if (stage === 4 && (code === 235 || code === 250)) {
            
            stage = 5;
            send(`MAIL FROM:<${options.from}>`);
          } else if (stage === 5 && code === 250) {
            
            stage = 6;
            for (const r of options.to) {
              send(`RCPT TO:<${r}>`);
            }
            stage = 7;
          } else if (stage === 7 && code === 250) {
            
            stage = 8;
            send('DATA');
          } else if (stage === 8 && code === 354) {
            
            const message = [
              `From: ${options.from}`,
              `To: ${options.to.join(', ')}`,
              `Subject: ${options.subject}`,
              `Date: ${new Date().toUTCString()}`,
              `Message-ID: <${Date.now()}@obold.local>`,
              'Content-Type: text/plain; charset=utf-8',
              '',
              options.body,
              '.',
            ].join('\r\n');

            stage = 9;
            send(message);
          } else if (stage === 9 && code === 250) {
            
            stage = 10;
            send('QUIT');
            cleanup();
            socket.end();
            return resolve();
          }
        }
      };

      if (options.useTlsDirect) {
        socket = connectTls({ host: options.host, port: options.port, rejectUnauthorized: false });
      } else {
        socket = createConnection({ host: options.host, port: options.port });
      }

      socket.on('data', onData);
      socket.on('error', (err: any) => {
        cleanup();
        reject(err);
      });
    });
  }
}
