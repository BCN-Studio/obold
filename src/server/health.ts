import type { OboldEngine } from '../core/engine.ts';

export class HealthHandler {
  private engine: OboldEngine;
  private bootTime: number;

  constructor(engine: OboldEngine) {
    this.engine = engine;
    this.bootTime = Date.now();
  }

  
  public getHealthz(): Response {
    return new Response(
      JSON.stringify({
        status: 'healthy',
        timestamp: Date.now(),
        uptimeSeconds: Math.floor((Date.now() - this.bootTime) / 1000),
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }

  
  public getReadyz(): Response {
    try {
      const db = this.engine.getDb();
      const testVal = db.getMetadata('schema_version');
      const isReady = testVal !== null;

      return new Response(
        JSON.stringify({
          ready: isReady,
          schemaVersion: testVal,
          switchesCount: this.engine.getRuntimeStates().length,
        }),
        {
          status: isReady ? 200 : 503,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    } catch (err: any) {
      return new Response(
        JSON.stringify({ ready: false, error: err.message }),
        {
          status: 503,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }
  }

  
  public getPrometheusMetrics(): Response {
    const states = this.engine.getRuntimeStates();
    const uptimeSec = Math.floor((Date.now() - this.bootTime) / 1000);
    const armedCount = states.filter((s) => s.status === 'ARMED').length;
    const triggeredCount = states.filter((s) => s.status === 'TRIGGERED').length;

    const lines = [
      '# HELP obold_uptime_seconds Total seconds the daemon has been running',
      '# TYPE obold_uptime_seconds counter',
      `obold_uptime_seconds ${uptimeSec}`,
      '',
      '# HELP obold_switches_total Total configured dead man switches',
      '# TYPE obold_switches_total gauge',
      `obold_switches_total ${states.length}`,
      '',
      '# HELP obold_switches_armed Number of currently armed switches',
      '# TYPE obold_switches_armed gauge',
      `obold_switches_armed ${armedCount}`,
      '',
      '# HELP obold_switches_triggered Number of switches currently triggered',
      '# TYPE obold_switches_triggered gauge',
      `obold_switches_triggered ${triggeredCount}`,
      '',
    ];

    for (const sw of states) {
      const remainingSeconds = Math.floor(sw.remainingMs / 1000);
      lines.push(`obold_switch_remaining_seconds{switch_id="${sw.id}",name="${sw.name}"} ${remainingSeconds}`);
    }

    return new Response(lines.join('\n') + '\n', {
      status: 200,
      headers: { 'Content-Type': 'text/plain; version=0.0.4' },
    });
  }
}
