import { connect as connectTls } from 'node:tls';
import { createConnection, Socket } from 'node:net';
import type { IPluginExecutor, PluginExecutionContext, ReplaySafety } from '../types.ts';
import type { ExecutionResult } from '../../config/types.ts';

export class EmailPlugin implements IPluginExecutor {
  readonly id = 'core:email';
  readonly name = 'SMTP Email Dispatcher';
  readonly description = 'Dispatches TLS-encrypted emails and attachments via standard SMTP servers.';
  readonly version = '1.0.0';
  readonly replaySafety: ReplaySafety = 'UNKNOWN';

  validateConfig(config: Record<string, any>): { valid: boolean; error?: string } {
    if (!config.smtp_host || typeof config.smtp_host !== 'string') {
      return { valid: false, error: 'Missing required field: "smtp_host".' };
    }
    if (!config.to || (Array.isArray(config.to) && config.to.length === 0)) {
      return { valid: false, error: 'Missing required field: "to" (recipient email array or string).' };
    }
    if (!config.subject || typeof config.subject !== 'string') {
      return { valid: false, error: 'Missing required field: "subject".' };
    }
    if (/[\r\n]/.test(config.subject)) {
      return { valid: false, error: 'Invalid character in "subject": newline characters are forbidden.' };
    }

    if (config.from && typeof config.from === 'string' && /[\r\n]/.test(config.from)) {
      return { valid: false, error: 'Invalid character in "from": newline characters are forbidden.' };
    }

    const recipients = Array.isArray(config.to) ? config.to : [config.to];
    for (const r of recipients) {
      if (typeof r !== 'string' || /[\r\n]/.test(r)) {
        return { valid: false, error: 'Invalid recipient in "to": newline characters are forbidden.' };
      }
    }

    if (config.smtp_port !== undefined) {
      const portNum = Number(config.smtp_port);
      if (isNaN(portNum) || portNum <= 0 || portNum > 65535) {
        return { valid: false, error: 'Invalid "smtp_port": must be a valid port number between 1 and 65535.' };
      }
    }

    if (typeof config.smtp_user === 'string' && config.smtp_user.startsWith('ENV:')) {
      const envKey = config.smtp_user.substring(4).trim();
      const val = process.env[envKey];
      if (!val || val.trim().length === 0) {
        return { valid: false, error: `Missing required environment variable "${envKey}" for SMTP credentials.` };
      }
    }

    if (typeof config.smtp_pass === 'string' && config.smtp_pass.startsWith('ENV:')) {
      const envKey = config.smtp_pass.substring(4).trim();
      const val = process.env[envKey];
      if (!val || val.trim().length === 0) {
        return { valid: false, error: `Missing required environment variable "${envKey}" for SMTP credentials.` };
      }
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

    const recipients = (Array.isArray(config.to) ? config.to : [config.to]).map((r: string) => r.trim());
    const fromAddr = (config.from || 'obold-daemon@bcnstudio.tech').trim();
    const subject = config.subject.trim();
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
    if (typeof smtpUser === 'string' && smtpUser.startsWith('ENV:')) {
      smtpUser = process.env[smtpUser.substring(4).trim()] || '';
    }

    let smtpPass = config.smtp_pass || '';
    if (typeof smtpPass === 'string' && smtpPass.startsWith('ENV:')) {
      smtpPass = process.env[smtpPass.substring(4).trim()] || '';
    }

    const host = config.smtp_host;
    const port = Number(config.smtp_port) || 587;
    const useTlsDirect = port === 465 || config.tls === true;
    const requireStarttls = !useTlsDirect && (port === 587 || config.starttls === true);
    const allowInsecureTls = config.allow_insecure_tls === true;

    try {
      await this.sendSmtp({
        host,
        port,
        useTlsDirect,
        requireStarttls,
        allowInsecureTls,
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
    requireStarttls: boolean;
    allowInsecureTls: boolean;
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
      let isSettled = false;

      const timer = setTimeout(() => {
        fail(new Error(`SMTP connection timed out after ${options.timeoutMs}ms`));
      }, options.timeoutMs);

      const fail = (err: Error) => {
        if (isSettled) return;
        isSettled = true;
        clearTimeout(timer);
        if (options.signal) {
          options.signal.removeEventListener('abort', abortHandler);
        }
        if (socket) {
          try {
            socket.destroy();
          } catch {}
        }
        reject(err);
      };

      const succeed = () => {
        if (isSettled) return;
        isSettled = true;
        clearTimeout(timer);
        if (options.signal) {
          options.signal.removeEventListener('abort', abortHandler);
        }
        if (socket) {
          try {
            socket.end();
          } catch {}
        }
        resolve();
      };

      const abortHandler = () => {
        fail(new Error('SMTP dispatch aborted by cancellation signal'));
      };

      if (options.signal) {
        if (options.signal.aborted) {
          clearTimeout(timer);
          return reject(new Error('SMTP dispatch aborted before connect'));
        }
        options.signal.addEventListener('abort', abortHandler, { once: true });
      }

      const send = (line: string) => {
        if (socket && !socket.destroyed) {
          socket.write(line + '\r\n');
        }
      };

      const handleLine = (code: number, line: string) => {
        if (code >= 400) {
          return fail(new Error(`SMTP server error [${code}]: ${line}`));
        }

        if (stage === 0 && code === 220) {
          stage = 1;
          send('EHLO obold.local');
        } else if (stage === 1 && code === 250) {
          if (options.requireStarttls) {
            stage = 2;
            send('STARTTLS');
          } else if (options.user && options.pass) {
            stage = 4;
            send('AUTH LOGIN');
          } else {
            stage = 6;
            send(`MAIL FROM:<${options.from}>`);
          }
        } else if (stage === 2 && code === 220) {
          stage = 3;
          upgradeToTls();
        } else if (stage === 3 && code === 250) {
          if (options.user && options.pass) {
            stage = 4;
            send('AUTH LOGIN');
          } else {
            stage = 6;
            send(`MAIL FROM:<${options.from}>`);
          }
        } else if (stage === 4 && code === 334) {
          stage = 5;
          send(Buffer.from(options.user).toString('base64'));
        } else if (stage === 5 && code === 334) {
          stage = 6;
          send(Buffer.from(options.pass).toString('base64'));
        } else if (stage === 6 && (code === 235 || code === 250)) {
          stage = 7;
          send(`MAIL FROM:<${options.from}>`);
        } else if (stage === 7 && code === 250) {
          stage = 8;
          for (const r of options.to) {
            send(`RCPT TO:<${r}>`);
          }
          stage = 9;
        } else if (stage === 9 && code === 250) {
          stage = 10;
          send('DATA');
        } else if (stage === 10 && code === 354) {
          const normalizedBody = options.body.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
          const stuffedBody = normalizedBody
            .split('\n')
            .map((l) => (l.startsWith('.') ? '.' + l : l))
            .join('\r\n');

          const message = [
            `From: ${options.from}`,
            `To: ${options.to.join(', ')}`,
            `Subject: ${options.subject}`,
            `Date: ${new Date().toUTCString()}`,
            `Message-ID: <${Date.now()}@obold.local>`,
            'MIME-Version: 1.0',
            'Content-Type: text/plain; charset=utf-8',
            'Content-Transfer-Encoding: 8bit',
            '',
            stuffedBody,
            '.',
          ].join('\r\n');

          stage = 11;
          send(message);
        } else if (stage === 11 && code === 250) {
          stage = 12;
          send('QUIT');
          succeed();
        }
      };

      const onData = (data: Buffer) => {
        buffer += data.toString('utf-8');
        const lines = buffer.split('\r\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (!line) continue;
          const code = parseInt(line.substring(0, 3), 10);
          if (line[3] === '-') continue;
          handleLine(code, line);
        }
      };

      const upgradeToTls = () => {
        const plainSocket = socket;
        plainSocket.removeListener('data', onData);
        plainSocket.removeListener('error', onError);

        const tlsSocket = connectTls({
          socket: plainSocket,
          host: options.host,
          rejectUnauthorized: !options.allowInsecureTls,
          servername: options.host,
        });

        socket = tlsSocket;
        buffer = '';

        tlsSocket.on('data', onData);
        tlsSocket.on('error', onError);
        tlsSocket.on('secureConnect', () => {
          send('EHLO obold.local');
        });
      };

      const onError = (err: any) => {
        fail(err);
      };

      if (options.useTlsDirect) {
        socket = connectTls({
          host: options.host,
          port: options.port,
          rejectUnauthorized: !options.allowInsecureTls,
          servername: options.host,
        });
      } else {
        socket = createConnection({ host: options.host, port: options.port });
      }

      socket.on('data', onData);
      socket.on('error', onError);
    });
  }
}
