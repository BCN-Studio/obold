export class SseEventBus {
  private clients = new Set<{ id: string; ip?: string; send: (data: string) => void }>();
  private ipCounts = new Map<string, number>();
  private maxClients: number;
  private maxPerIp: number;

  constructor(maxClients: number = 32, maxPerIp: number = 4) {
    this.maxClients = maxClients;
    this.maxPerIp = maxPerIp;
  }

  public handleConnection(corsHeaders: Record<string, string> = {}, clientIp?: string): Response {
    if (this.clients.size >= this.maxClients) {
      return new Response(JSON.stringify({ error: 'Too Many Requests: Maximum concurrent SSE connections reached.' }), {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': '60',
          ...corsHeaders,
        },
      });
    }

    if (clientIp) {
      const currentIpCount = this.ipCounts.get(clientIp) || 0;
      if (currentIpCount >= this.maxPerIp) {
        return new Response(JSON.stringify({ error: 'Too Many Requests: Per-IP SSE connection limit exceeded.' }), {
          status: 429,
          headers: {
            'Content-Type': 'application/json',
            'Retry-After': '60',
            ...corsHeaders,
          },
        });
      }
      this.ipCounts.set(clientIp, currentIpCount + 1);
    }

    let clientObj: { id: string; ip?: string; send: (data: string) => void };
    let heartbeatInterval: ReturnType<typeof setInterval> | null = null;

    const stream = new ReadableStream({
      start: (controller) => {
        const id = `sse-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
        clientObj = {
          id,
          ip: clientIp,
          send: (data: string) => {
            try {
              controller.enqueue(new TextEncoder().encode(`data: ${data}\n\n`));
            } catch {
              this.removeClient(clientObj);
            }
          },
        };
        this.clients.add(clientObj);

        clientObj.send(JSON.stringify({ type: 'connected', timestamp: Date.now() }));

        heartbeatInterval = setInterval(() => {
          try {
            controller.enqueue(new TextEncoder().encode(`: keepalive ${Date.now()}\n\n`));
          } catch {
            if (heartbeatInterval) {
              clearInterval(heartbeatInterval);
              heartbeatInterval = null;
            }
            this.removeClient(clientObj);
          }
        }, 15000);
      },
      cancel: () => {
        if (heartbeatInterval) {
          clearInterval(heartbeatInterval);
          heartbeatInterval = null;
        }
        if (clientObj) this.removeClient(clientObj);
      },
    });

    return new Response(stream, {
      headers: {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        ...corsHeaders,
      },
    });
  }

  public broadcast(eventType: string, payload: Record<string, any>): void {
    const message = JSON.stringify({ type: eventType, data: payload, timestamp: Date.now() });
    for (const client of this.clients) {
      try {
        client.send(message);
      } catch {
        this.removeClient(client);
      }
    }
  }

  private removeClient(client: { id: string; ip?: string; send: (data: string) => void }): void {
    if (this.clients.has(client)) {
      this.clients.delete(client);
      if (client.ip) {
        const count = this.ipCounts.get(client.ip) || 1;
        if (count <= 1) {
          this.ipCounts.delete(client.ip);
        } else {
          this.ipCounts.set(client.ip, count - 1);
        }
      }
    }
  }

  public getConnectedClientCount(): number {
    return this.clients.size;
  }
}
