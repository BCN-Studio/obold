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
      this.db.logAudit('FATAL', 'UNCAUGHT_EXCEPTION', `Process encountered an uncaught error: ${err.message}`, {
        stack: err.stack,
      });
      this.db.checkpoint();
      
      setTimeout(() => process.exit(1), 100);
    });

    process.on('unhandledRejection', (reason: any) => {
      this.db.logAudit('ERROR', 'UNHANDLED_REJECTION', `Unhandled promise rejection: ${reason?.message || reason}`);
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
