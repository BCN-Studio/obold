import type { OboldDatabase } from '../db/database.ts';

export class OboldWatchdog {
  private db: OboldDatabase;
  private isRunning: boolean = false;
  private heartbeatInterval: ReturnType<typeof setInterval> | null = null;

  constructor(db: OboldDatabase) {
    this.db = db;
  }

  
  public installProcessGuards(): void {
    process.on('uncaughtException', (err: Error) => {
      try {
        console.error('FATAL UNCAUGHT EXCEPTION:', err?.stack || err);
      } catch {}
      process.exit(1);
    });

    process.on('unhandledRejection', (reason: any) => {
      const reasonStr = String(reason?.stack || reason?.message || reason);
      try {
        console.error('UNHANDLED REJECTION:', reasonStr);
        this.db.logAudit('ERROR', 'UNHANDLED_REJECTION', `Unhandled promise rejection: ${reason?.message || reason}`);
      } catch {}
      if (/database disk image is malformed|sqlite|corrupt|fatal|panic/i.test(reasonStr)) {
        process.exit(1);
      }
    });
  }

  
  public startHeartbeat(intervalMs: number = 10000): void {
    if (this.isRunning) return;
    this.isRunning = true;

    this.db.setMetadata('watchdog_last_heartbeat', Date.now().toString());
    this.heartbeatInterval = setInterval(() => {
      this.db.setMetadata('watchdog_last_heartbeat', Date.now().toString());
    }, intervalMs);
  }

  
  public stopHeartbeat(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
      this.isRunning = false;
    }
  }
}
