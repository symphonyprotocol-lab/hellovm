/**
 * A scripted HTTP/1.1 server on loopback for the unit tests: each request
 * goes to a handler that may answer, stall, trickle, drop the connection
 * or send too much.
 */

import * as net from "node:net";

export interface Request {
  method: string;
  target: string;
  path: string;
  query: URLSearchParams;
  headers: Record<string, string>;
  body: Buffer;
}

export class Conn {
  closed = false;
  constructor(readonly socket: net.Socket) {}

  send(status: number, body: Buffer | string = "", headers: Record<string, string> = {}): void {
    const data = Buffer.from(body);
    const all = { "Content-Length": String(data.length), ...headers };
    const head = [`HTTP/1.1 ${status} X`, ...Object.entries(all).map(([k, v]) => `${k}: ${v}`)].join("\r\n");
    this.socket.write(Buffer.concat([Buffer.from(`${head}\r\n\r\n`), data]));
  }

  json(status: number, value: unknown): void {
    this.send(status, JSON.stringify(value), { "Content-Type": "application/json" });
  }

  error(status: number, code: string, message = "m"): void {
    this.json(status, { error: { code, message } });
  }

  raw(data: string | Buffer): void {
    this.socket.write(data);
  }

  drop(): void {
    this.closed = true;
    this.socket.destroy();
  }
}

export type Handler = (req: Request, conn: Conn) => void | Promise<void>;

export class FakeServer {
  readonly requests: Request[] = [];
  connections = 0;
  readonly #server: net.Server;
  readonly #sockets = new Set<net.Socket>();
  url = "";

  constructor(readonly handler: Handler) {
    this.#server = net.createServer((socket) => this.#serve(socket));
  }

  static async start(handler: Handler): Promise<FakeServer> {
    const server = new FakeServer(handler);
    await new Promise<void>((resolve) => server.#server.listen(0, "127.0.0.1", resolve));
    const address = server.#server.address() as net.AddressInfo;
    server.url = `http://127.0.0.1:${address.port}`;
    return server;
  }

  async close(): Promise<void> {
    for (const s of this.#sockets) s.destroy();
    await new Promise<void>((resolve) => this.#server.close(() => resolve()));
  }

  #serve(socket: net.Socket): void {
    this.connections++;
    this.#sockets.add(socket);
    socket.on("close", () => this.#sockets.delete(socket));
    socket.on("error", () => {});
    const conn = new Conn(socket);
    let buf = Buffer.alloc(0);
    let busy = false;
    const pump = async () => {
      if (busy) return;
      busy = true;
      try {
        for (;;) {
          const end = buf.indexOf("\r\n\r\n");
          if (end < 0) return;
          const lines = buf.subarray(0, end).toString("latin1").split("\r\n");
          const [method = "", target = ""] = (lines[0] ?? "").split(" ");
          const headers: Record<string, string> = {};
          for (const line of lines.slice(1)) {
            const at = line.indexOf(":");
            headers[line.slice(0, at).trim().toLowerCase()] = line.slice(at + 1).trim();
          }
          const length = Number(headers["content-length"] ?? "0");
          if (buf.length < end + 4 + length) return;
          const body = buf.subarray(end + 4, end + 4 + length);
          buf = buf.subarray(end + 4 + length);
          const url = new URL(target, "http://x");
          const req = { method, target, path: url.pathname, query: url.searchParams, headers, body };
          this.requests.push(req);
          await this.handler(req, conn);
          if (conn.closed) return;
        }
      } finally {
        busy = false;
      }
    };
    socket.on("data", (data) => {
      buf = Buffer.concat([buf, data]);
      void pump();
    });
  }
}
