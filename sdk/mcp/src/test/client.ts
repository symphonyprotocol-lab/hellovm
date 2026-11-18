/**
 * A minimal MCP client for the tests: spawns the server and speaks
 * newline-delimited JSON-RPC to it by hand, so that the tests check the
 * wire format itself (not what an SDK client would paper over). Keeps
 * every byte the server wrote, to look for the token in it.
 */

import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

export const SERVER = fileURLToPath(new URL("../server.js", import.meta.url));
export const MODERN = "2026-07-28";

export interface RpcResponse {
  jsonrpc: "2.0";
  id: number | string;
  result?: Record<string, unknown>;
  error?: { code: number; message: string; data?: unknown };
}

export interface ToolResult {
  content: { type: string; text: string }[];
  isError?: boolean;
}

export class McpProcess {
  readonly child: ChildProcessWithoutNullStreams;
  stdout = "";
  stderr = "";
  readonly #waiting = new Map<number | string, (r: RpcResponse) => void>();
  readonly messages: unknown[] = [];
  #nextId = 1;
  readonly exited: Promise<number | null>;

  constructor(env: Record<string, string>, readonly era: "modern" | "legacy" = "modern") {
    this.child = spawn(process.execPath, [SERVER], {
      env: { PATH: process.env.PATH ?? "", ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let buf = "";
    this.child.stdout.setEncoding("utf8");
    this.child.stdout.on("data", (chunk: string) => {
      this.stdout += chunk;
      buf += chunk;
      let at: number;
      while ((at = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, at);
        buf = buf.slice(at + 1);
        if (!line.trim()) continue;
        const message = JSON.parse(line) as RpcResponse;
        this.messages.push(message);
        const resolve = this.#waiting.get(message.id);
        if (resolve) {
          this.#waiting.delete(message.id);
          resolve(message);
        }
      }
    });
    this.child.stderr.setEncoding("utf8");
    this.child.stderr.on("data", (chunk: string) => {
      this.stderr += chunk;
    });
    this.exited = new Promise((resolve) => this.child.on("exit", (code) => resolve(code)));
  }

  send(message: unknown): void {
    this.child.stdin.write(`${JSON.stringify(message)}\n`);
  }

  /** The `_meta` a 2026-07-28 request carries. */
  static meta(): Record<string, unknown> {
    return {
      "io.modelcontextprotocol/protocolVersion": MODERN,
      "io.modelcontextprotocol/clientCapabilities": {},
      "io.modelcontextprotocol/clientInfo": { name: "hellovm-tests", version: "0" },
    };
  }

  /** Sends a request (with the modern `_meta` unless legacy) and waits for its answer. */
  request(method: string, params: Record<string, unknown> = {}, id: number | string = this.#nextId++, timeoutMs = 120_000): Promise<RpcResponse> {
    const full = this.era === "modern" ? { ...params, _meta: { ...McpProcess.meta(), ...((params._meta as object) ?? {}) } } : params;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`no answer to ${method} within ${timeoutMs} ms\n${this.stderr}`)), timeoutMs);
      this.#waiting.set(id, (r) => {
        clearTimeout(timer);
        resolve(r);
      });
      this.send({ jsonrpc: "2.0", id, method, params: full });
    });
  }

  /** The legacy (2025-11-25) opening handshake. */
  async initialize(): Promise<RpcResponse> {
    const r = await this.request("initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "hellovm-tests", version: "0" },
    });
    this.send({ jsonrpc: "2.0", method: "notifications/initialized" });
    return r;
  }

  async call(name: string, args: Record<string, unknown> = {}): Promise<ToolResult> {
    const r = await this.request("tools/call", { name, arguments: args });
    if (r.error) throw new Error(`tools/call ${name}: ${JSON.stringify(r.error)}`);
    return r.result as unknown as ToolResult;
  }

  /** Closes stdin and waits for the exit. */
  async close(): Promise<number | null> {
    this.child.stdin.end();
    const timer = setTimeout(() => this.child.kill("SIGKILL"), 20_000);
    const code = await this.exited;
    clearTimeout(timer);
    return code;
  }
}

export function text(r: ToolResult): string {
  return r.content.map((c) => c.text).join("\n");
}
