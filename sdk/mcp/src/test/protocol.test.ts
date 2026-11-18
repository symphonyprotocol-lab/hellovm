/**
 * The MCP server without a plane: the protocol in both eras, the tool
 * list and its schemas, configuration errors, the formatting of results,
 * and errors from a fake API (with the token kept out of everything the
 * server writes).
 */

import assert from "node:assert/strict";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { after, describe, test } from "node:test";

import type { ExecResult } from "hellovm";

import { fromEnv } from "../config.js";
import { formatExec, formatFile, formatPython, omission, redact, truncateBytes } from "../format.js";
import { MODERN, McpProcess, text } from "./client.js";

const TOKEN = "mcp-secret-token-0123456789abcdef";
const procs: McpProcess[] = [];
after(async () => {
  for (const p of procs) await p.close().catch(() => {});
});

function start(env: Record<string, string> = {}, era: "modern" | "legacy" = "modern"): McpProcess {
  const p = new McpProcess({ HELLOVM_URL: "http://127.0.0.1:9", HELLOVM_TOKEN: TOKEN, ...env }, era);
  procs.push(p);
  return p;
}

const TOOLS = ["exec", "python", "read_file", "write_file", "edit_file", "reset_sandbox"];

function result(over: Partial<ExecResult> = {}): ExecResult {
  return {
    execId: "ex-1",
    exitCode: 0,
    signal: null,
    timedOut: false,
    cancelled: false,
    stdout: "",
    stderr: "",
    stdoutTruncated: false,
    stderrTruncated: false,
    stdoutBytes: 0,
    stderrBytes: 0,
    durationMs: 1,
    value: null,
    error: null,
    stateLost: null,
    ok: true,
    ...over,
  };
}

describe("the protocol", () => {
  test("2026-07-28: server/discover, then tools/list with schemas", async () => {
    const p = start();
    const d = await p.request("server/discover");
    assert.equal(d.result?.resultType, "complete");
    assert.ok((d.result?.supportedVersions as string[]).includes(MODERN));
    assert.ok((d.result?.capabilities as { tools?: unknown }).tools);
    assert.match(String(d.result?.instructions), /sandbox/);
    const list = await p.request("tools/list");
    const tools = list.result?.tools as { name: string; description: string; inputSchema: { type: string; properties: Record<string, unknown>; required?: string[] }; annotations?: Record<string, boolean> }[];
    assert.deepEqual(tools.map((t) => t.name), TOOLS);
    const byName = Object.fromEntries(tools.map((t) => [t.name, t]));
    assert.deepEqual(byName.exec?.inputSchema.required, ["command"]);
    assert.deepEqual(Object.keys(byName.exec?.inputSchema.properties ?? {}).sort(), ["command", "cwd", "timeout"]);
    assert.equal((byName.exec?.inputSchema.properties.timeout as { maximum: number }).maximum, 600);
    assert.deepEqual(byName.python?.inputSchema.required, ["code"]);
    assert.deepEqual(byName.edit_file?.inputSchema.required?.sort(), ["new_text", "old_text", "path"]);
    assert.equal(byName.read_file?.annotations?.readOnlyHint, true);
    for (const t of tools) {
      assert.equal(t.inputSchema.type, "object");
      assert.ok(t.description.length > 20);
    }
    // A request without the per-request fields is refused.
    p.send({ jsonrpc: "2.0", id: "bare", method: "tools/list", params: {} });
    const bare = await new Promise<{ error?: { code: number } }>((resolve) => {
      const check = setInterval(() => {
        const m = p.messages.find((x) => (x as { id?: unknown }).id === "bare");
        if (m) {
          clearInterval(check);
          resolve(m as { error?: { code: number } });
        }
      }, 10);
    });
    assert.ok(bare.error, JSON.stringify(bare));
    assert.equal((await p.request("no/such/method")).error?.code, -32601);
    // An unsupported version, as the opening request.
    const q = start();
    const old = await q.request("tools/list", { _meta: { "io.modelcontextprotocol/protocolVersion": "1900-01-01" } });
    assert.equal(old.error?.code, -32022);
    assert.ok((old.error?.data as { supported: string[] }).supported.includes(MODERN));
  });

  test("2025-11-25: the initialize handshake still works", async () => {
    const p = start({}, "legacy");
    const init = await p.initialize();
    assert.equal(init.result?.protocolVersion, "2025-11-25");
    assert.deepEqual(init.result?.serverInfo, { name: "hellovm", version: "0.0.1" });
    const list = await p.request("tools/list");
    assert.deepEqual((list.result?.tools as { name: string }[]).map((t) => t.name), TOOLS);
  });

  test("bad arguments and unknown tools", async () => {
    const p = start();
    const bad = await p.request("tools/call", { name: "exec", arguments: { command: "true", timeout: 100000 } });
    const badResult = bad.result as { isError?: boolean } | undefined;
    assert.ok(bad.error?.code === -32602 || badResult?.isError === true, JSON.stringify(bad));
    const unknown = await p.request("tools/call", { name: "rm_rf", arguments: {} });
    assert.ok(unknown.error || (unknown.result as { isError?: boolean }).isError, JSON.stringify(unknown));
  });

  test("the server exits when stdin closes", async () => {
    const p = start();
    await p.request("server/discover");
    assert.equal(await p.close(), 0);
  });

  test("configuration errors are reported without the token", async () => {
    const p = new McpProcess({ HELLOVM_TOKEN: TOKEN });
    assert.equal(await p.exited, 2);
    assert.match(p.stderr, /HELLOVM_URL/);
    const q = new McpProcess({ HELLOVM_URL: "http://127.0.0.1:9", HELLOVM_TOKEN: TOKEN, HELLOVM_MCP_MAX_TIMEOUT: "-3" });
    assert.equal(await q.exited, 2);
    assert.ok(!q.stderr.includes(TOKEN));
    assert.throws(() => fromEnv({ HELLOVM_URL: "http://x" }), /HELLOVM_TOKEN/);
    const c = fromEnv({ HELLOVM_URL: "http://x", HELLOVM_TOKEN: "t", HELLOVM_MCP_TIMEOUT: "900" });
    assert.equal(c.defaultTimeout, 600);
    assert.equal(c.maxOutput, 16384);
  });
});

describe("against a fake API", () => {
  test("API errors are tool errors with the API's message, and the token never leaks", async () => {
    const seen: string[] = [];
    const api = http.createServer((req, res) => {
      seen.push(`${req.method} ${req.url} ${req.headers.authorization === `Bearer ${TOKEN}` ? "auth-ok" : "auth-bad"}`);
      if (req.method === "POST" && req.url === "/v1/sandboxes") {
        res.writeHead(201, { "content-type": "application/json" });
        res.end(JSON.stringify({ id: "sb-" + "cd".repeat(16), tenant: "t", template: "python", node: "n", egress_id: "cdcdcdcdcdcdcdcd", created_at: 1, last_used_at: 1, expires_at: 1, idle_timeout: 600, memory_bytes: 0, memory_limit_bytes: 1, ready_ms: 1 }));
        return;
      }
      if (req.method === "GET" && req.url?.includes("/files?")) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { code: "not_found", message: `no such file (and a careless echo of ${TOKEN})` } }));
        return;
      }
      if (req.method === "DELETE") {
        res.writeHead(204);
        res.end();
        return;
      }
      res.writeHead(507, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { code: "no_space", message: "the writable layer is full" } }));
    });
    await new Promise<void>((resolve) => api.listen(0, "127.0.0.1", resolve));
    after(() => api.close());
    const url = `http://127.0.0.1:${(api.address() as AddressInfo).port}`;
    const p = start({ HELLOVM_URL: url });
    const read = await p.call("read_file", { path: "/nope" });
    assert.equal(read.isError, true);
    assert.match(text(read), /404 not_found/);
    assert.match(text(read), /\[redacted\]/);
    const write = await p.call("write_file", { path: "/x", content: "y" });
    assert.equal(write.isError, true);
    assert.match(text(write), /Error \(507 no_space\): the writable layer is full/);
    assert.equal(await p.close(), 0);
    assert.ok(seen.every((s) => s.endsWith("auth-ok")), seen.join("\n"));
    assert.ok(seen.some((s) => s.startsWith("DELETE")), "the sandbox is deleted at exit");
    assert.ok(!p.stdout.includes(TOKEN));
    assert.ok(!p.stderr.includes(TOKEN));
  });

  test("an unreachable API is a tool error", async () => {
    const closed = http.createServer();
    await new Promise<void>((resolve) => closed.listen(0, "127.0.0.1", resolve));
    const port = (closed.address() as AddressInfo).port;
    await new Promise((resolve) => closed.close(resolve));
    const p = start({ HELLOVM_URL: `http://127.0.0.1:${port}` });
    const r = await p.call("exec", { command: "true" });
    assert.equal(r.isError, true);
    assert.match(text(r), /Could not create a sandbox: Error: cannot connect to the API/);
    assert.ok(!p.stdout.includes(TOKEN) && !p.stderr.includes(TOKEN));
  });
});

describe("formatting", () => {
  test("exec results state the outcome first", () => {
    assert.equal(formatExec(result({ stdout: "hi\n" }), 60), "Exit code: 0\n--- stdout ---\nhi\n--- end of stdout ---\n--- stderr: empty ---");
    assert.match(formatExec(result({ exitCode: 3, stderr: "bad" }), 60), /^Exit code: 3\n[^]*--- stderr ---\nbad\n--- end of stderr ---$/);
    assert.match(formatExec(result({ exitCode: null, signal: 9, timedOut: true }), 5), /^Timed out after 5 s: the command was killed \(signal 9\)\./);
    assert.match(formatExec(result({ exitCode: null, signal: 11 }), 5), /^Killed by signal 11\./);
    const cut = formatExec(result({ stdout: "aa" + omission(96) + "bb", stdoutTruncated: true, stdoutBytes: 100 }), 5);
    assert.match(cut, /--- stdout \(100 bytes in all, too long: only its start and end are shown/);
    assert.match(cut, /\[\.\.\. 96 bytes omitted \.\.\.\]/);
  });

  test("python results", () => {
    assert.equal(formatPython(result({ value: "42" }), 60), "Value: 42");
    assert.equal(formatPython(result(), 60), "Done (no value).");
    const raised = formatPython(result({ exitCode: 1, error: { type: "ZeroDivisionError", message: "division by zero", traceback: "Traceback (most recent call last):\n  ...\n" } }), 60);
    assert.match(raised, /^Raised ZeroDivisionError: division by zero\nTraceback/);
    const lost = formatPython(result({ timedOut: true, stateLost: true, error: { type: "InterpreterKilled", message: "m", traceback: "" } }), 2);
    assert.match(lost, /^Timed out after 2 s and was interrupted\./);
    assert.match(lost, /state was lost/);
  });

  test("files", () => {
    const enc = (s: string) => new TextEncoder().encode(s);
    assert.equal(formatFile("a", enc("hello\n"), 100), "hello\n");
    assert.equal(formatFile("a", new Uint8Array(), 100), "a is empty.");
    assert.match(formatFile("a", new Uint8Array([0xff, 0xfe, 0]), 100), /binary file \(3 bytes/);
    const long = formatFile("big.txt", enc("x".repeat(1000)), 100);
    assert.ok(long.startsWith("x".repeat(50) + "\n[... 900 bytes omitted ...]\n" + "x".repeat(50)));
    assert.match(long, /big\.txt is 1000 bytes, too long/);
    const t = truncateBytes(enc("0123456789abcdef"), 10);
    assert.equal(new TextDecoder().decode(t.bytes), "01234\n[... 6 bytes omitted ...]\nbcdef");
    assert.equal(t.omitted, 6);
    assert.equal(redact(`a ${TOKEN} b ${TOKEN}`, TOKEN), "a [redacted] b [redacted]");
  });
});
