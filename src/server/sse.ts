export class SseEventBus {
  private clients = new Set<{ id: string; send: (data: string) => void }>();

  public handleConnection(corsHeaders: Record<string, string> = {}): Response {
    let clientObj: { id: string; send: (data: string) => void };

    const stream = new ReadableStream({
      start: (controller) => {
        const id = `sse-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
        clientObj = {
          id,
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
      },
      cancel: () => {
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

  private removeClient(client: { id: string; send: (data: string) => void }): void {
    this.clients.delete(client);
  }

  public getConnectedClientCount(): number {
    return this.clients.size;
  }
}
