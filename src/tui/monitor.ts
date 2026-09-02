import type { OboldEngine } from '../core/engine.ts';
import type { OboldDatabase } from '../db/database.ts';
import { formatMsToDuration } from '../config/loader.ts';

export interface MonitorOptions {
  engine: OboldEngine;
  db: OboldDatabase;
  refreshIntervalMs?: number;
}

const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  white: '\x1b[97m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  gray: '\x1b[90m',
  bgDark: '\x1b[40m',
  inverse: '\x1b[7m',
};

export async function startInteractiveMonitor(options: MonitorOptions): Promise<void> {
  const { engine, db } = options;
  const intervalMs = options.refreshIntervalMs || 1000;

  process.stdout.write('\x1b[?1049h\x1b[?25l\x1b[2J');

  let selectedIndex = 0;
  let statusMessage = '';
  let statusTimer: ReturnType<typeof setTimeout> | null = null;
  let isRunning = true;

  function showStatus(msg: string, durationMs: number = 3000) {
    statusMessage = msg;
    if (statusTimer) clearTimeout(statusTimer);
    statusTimer = setTimeout(() => {
      statusMessage = '';
      render();
    }, durationMs);
    render();
  }

  function cleanup() {
    if (!isRunning) return;
    isRunning = false;
    if (statusTimer) clearTimeout(statusTimer);
    clearInterval(timer);
    process.stdin.setRawMode(false);
    process.stdin.pause();
    process.stdout.write('\x1b[?25h\x1b[?1049l');
    process.exit(0);
  }

  function renderProgressBar(fraction: number, width: number = 14): string {
    const clamped = Math.max(0, Math.min(1, fraction));
    const filled = Math.round(clamped * width);
    const empty = width - filled;
    const bar = '█'.repeat(filled) + '░'.repeat(empty);
    const pct = Math.round(clamped * 100).toString().padStart(3, ' ');
    return `[${bar}] ${pct}%`;
  }

  function render() {
    if (!isRunning) return;

    const termWidth = process.stdout.columns || 80;
    const termHeight = process.stdout.rows || 24;
    const states = engine.getRuntimeStates();
    const logs = db.getAuditLogs(6);

    let out = '\x1b[H';

    const headerTitle = ` 🪙  OBOLD TERMINAL MONITOR — SOVEREIGN EMERGENCY CONTINUITY DAEMON (v1.0.0-beta) `;
    const timeStr = new Date().toLocaleTimeString();
    out += `${C.bgDark}${C.bold}${C.white}${headerTitle.padEnd(termWidth - timeStr.length - 1, ' ')}${C.gray}${timeStr} ${C.reset}\n`;
    out += `${C.gray}${'━'.repeat(termWidth)}${C.reset}\n`;

    out += `${C.bold}${C.white} ACTIVE DEAD MAN SWITCHES (${states.length})${C.reset}\n`;
    const colId = 'SWITCH ID'.padEnd(16, ' ');
    const colName = 'NAME'.padEnd(18, ' ');
    const colStatus = 'STATUS'.padEnd(14, ' ');
    const colRemaining = 'REMAINING'.padEnd(15, ' ');
    const colProgress = 'COUNTDOWN GAUGE'.padEnd(24, ' ');
    const colRetries = 'RETRIES';
    out += `${C.dim}${colId} ${colName} ${colStatus} ${colRemaining} ${colProgress} ${colRetries}${C.reset}\n`;
    out += `${C.gray}${'─'.repeat(termWidth)}${C.reset}\n`;

    if (states.length === 0) {
      out += `  ${C.gray}No switches configured in obold.yaml${C.reset}\n`;
    } else {
      states.forEach((sw, idx) => {
        const isSelected = idx === selectedIndex;
        const prefix = isSelected ? `${C.cyan}▸ ` : '  ';

        let statusBadge: string = sw.status;
        if (sw.status === 'ARMED') statusBadge = `${C.green}● ARMED${C.reset}`;
        else if (sw.status === 'PAUSED') statusBadge = `${C.yellow}⏸ PAUSED${C.reset}`;
        else if (sw.status === 'GRACE_PERIOD') statusBadge = `${C.yellow}⚠ GRACE${C.reset}`;
        else if (sw.status === 'TRIGGERED') statusBadge = `${C.red}✖ TRIPPED${C.reset}`;
        else statusBadge = `${C.gray}○ DISARMED${C.reset}`;

        const remainingStr = sw.status === 'PAUSED' ? 'PAUSED' : formatMsToDuration(sw.remainingMs);
        const totalInterval = (sw as any).intervalMs || (sw.nextDeadlineAt - sw.lastCheckinAt) || 86400000;
        const fraction = totalInterval > 0 ? sw.remainingMs / totalInterval : 0;
        const progressGauge = sw.status === 'PAUSED' ? `${C.yellow}[  PAUSED MODE  ]${C.reset}` : renderProgressBar(fraction, 14);
        const retriesStr = sw.pendingRetries > 0 ? `${C.red}${sw.pendingRetries}${C.reset}` : `${C.gray}0${C.reset}`;

        const rowStr = `${prefix}${sw.id.padEnd(14, ' ')} ${sw.name.padEnd(18, ' ')} ${statusBadge.padEnd(22, ' ')} ${remainingStr.padEnd(15, ' ')} ${progressGauge}   ${retriesStr}`;
        out += `${isSelected ? C.bold : ''}${rowStr}${C.reset}\n`;

        if (isSelected && sw.status === 'PAUSED' && (sw.pausedUntil || sw.pauseReason)) {
          const pauseDetails = `    └─ Reason: ${sw.pauseReason || 'None'} • Resumes: ${sw.pausedUntil ? new Date(sw.pausedUntil).toLocaleString() : 'Indefinite'}`;
          out += `${C.dim}${C.yellow}${pauseDetails}${C.reset}\n`;
        }
      });
    }

    out += `\n${C.gray}${'━'.repeat(termWidth)}${C.reset}\n`;
    out += `${C.bold}${C.white} RECENT AUDIT LEDGER LOGS${C.reset}\n`;
    out += `${C.gray}${'─'.repeat(termWidth)}${C.reset}\n`;

    if (logs.length === 0) {
      out += `  ${C.gray}No audit records logged yet.${C.reset}\n`;
    } else {
      logs.forEach((log) => {
        const time = new Date(log.created_at).toLocaleTimeString();
        let levelTag = `[${log.level}]`;
        if (log.level === 'INFO') levelTag = `${C.green}[INFO]${C.reset}`;
        else if (log.level === 'WARN') levelTag = `${C.yellow}[WARN]${C.reset}`;
        else if (log.level === 'ERROR' || log.level === 'FATAL') levelTag = `${C.red}[${log.level}]${C.reset}`;

        const msgSnippet = log.message.substring(0, termWidth - 32);
        out += `  ${C.gray}${time}${C.reset} ${levelTag.padEnd(15, ' ')} ${C.dim}${log.category.padEnd(18, ' ')}${C.reset} ${msgSnippet}\n`;
      });
    }

    const availableRows = termHeight - (states.length * 2 + logs.length + 9);
    if (availableRows > 0) {
      out += '\n'.repeat(availableRows);
    }

    out += `\n${C.gray}${'━'.repeat(termWidth)}${C.reset}\n`;
    if (statusMessage) {
      out += `${C.bold}${C.yellow} 🔔 ${statusMessage}${C.reset}\n`;
    } else {
      out += `${C.dim} [↑/↓] Select Switch  •  [c] Check-in  •  [p] Pause/Resume  •  [t] Trigger (Dry-Run)  •  [r] Refresh  •  [q] Quit${C.reset}\n`;
    }

    process.stdout.write(out);
  }

  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.setEncoding('utf-8');

  process.stdin.on('data', async (key: string) => {
    const states = engine.getRuntimeStates();

    if (key === 'q' || key === 'Q' || key === '\u0003') {
      cleanup();
      return;
    }

    if (key === '\u001b[A' || key === 'k') {
      if (selectedIndex > 0) selectedIndex--;
      render();
      return;
    }

    if (key === '\u001b[B' || key === 'j') {
      if (selectedIndex < states.length - 1) selectedIndex++;
      render();
      return;
    }

    if (key === 'r' || key === 'R') {
      showStatus('Refreshed state ledger.');
      return;
    }

    const selectedSwitch = states[selectedIndex];
    if (!selectedSwitch) return;

    if (key === 'c' || key === 'C') {
      const res = await engine.checkin(selectedSwitch.id);
      if (res.success) {
        showStatus(`Checked in switch "${selectedSwitch.id}". Countdown extended!`);
      } else {
        showStatus(`Failed to check in: Switch not found.`);
      }
      return;
    }

    if (key === 'p' || key === 'P') {
      if (selectedSwitch.status === 'PAUSED') {
        engine.resumeSwitch(selectedSwitch.id);
        showStatus(`Switch "${selectedSwitch.id}" RESUMED active countdown.`);
      } else {
        engine.pauseSwitch(selectedSwitch.id, undefined, 'Paused via TUI monitor');
        showStatus(`Switch "${selectedSwitch.id}" PAUSED indefinitely.`);
      }
      return;
    }

    if (key === 't' || key === 'T') {
      try {
        await engine.triggerSwitch(selectedSwitch.id, true);
        showStatus(`[DRY-RUN] Simulated trigger test executed for "${selectedSwitch.id}".`);
      } catch (err: any) {
        showStatus(`Trigger failed: ${err.message}`);
      }
      return;
    }
  });

  process.stdout.on('resize', render);
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);

  render();
  const timer = setInterval(render, intervalMs);
}
