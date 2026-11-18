/**
 * Unit tests: parsing, the retry rules, and the client against a local
 * fake server that answers, stalls, trickles, drops connections or sends
 * too much. No sandbox is needed.
 */

import assert from "node:assert/strict";
import * as net from "node:net";
import { after, describe, test } from "node:test";
import { inspect } from "node:util";

import {
  AbortedError,
  APIError,
  AuthenticationError,
  BudgetExceededError,
  BusyError,
  Client,
  EditError,
  LimitError,
  NotFoundError,
  RateLimitError,
  RequestTimeoutError,
  ResponseError,
  SandboxEndedError,
  TransportError,
  type StreamEvent,
} from "../index.js";
import { apiError, retryAfter } from "../errors.js";
import { parseEvent, parsePoll, parseResult, parseSandbox, parseUsage } from "../model.js";
import * as retry from "../retry.js";
import { type Conn, FakeServer, type Request } from "./fakeserver.js";

const SB = "sb-" + "ab".repeat(16);
const TOKEN = "unit-token-0123456789abcdef";

function result(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    exec_id: "ex-1",
    exit_code: 0,
    signal: null,
    timed_out: false,
    cancelled: false,
    stdout: "hi\n",
    stderr: "",
    stdout_truncated: false,
    stderr_truncated: false,
    stdout_bytes: 3,
    stderr_bytes: 0,
    duration_ms: 1.5,
    ...over,
  };
}

function counters(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { run_ms: 10, cpu_ms: 3, memory_byte_seconds: 4, egress_sent_bytes: 1, egress_received_bytes: 5, ...over };
}

function tenantUsage(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    tenant: "acme",
    period: { start: 1000, end: 2000, seconds: 1 },
    usage: counters(),
    sandboxes: 1,
    memory_limit_bytes: 2 ** 30,
    quotas: {
      max_sandboxes: 3,
      max_memory_bytes: null,
      requests_per_second: 2.5,
      request_burst: 10,
      cpu_seconds_per_period: 1.5,
      egress_bytes_per_period: null,
    },
    exceeded: ["cpu"],
    ...over,
  };
}

function info(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: SB,
    tenant: "acme",
    template: "python",
    node: "node-1",
    egress_id: "abababababababab",
    created_at: 1,
    last_used_at: 2,
    expires_at: 3,
    idle_timeout: 600,
    memory_bytes: 10,
    memory_limit_bytes: 20,
    ready_ms: 7.5,
    ...over,
  };
}

const servers: FakeServer[] = [];
after(async () => {
  await Promise.all(servers.map((s) => s.close()));
});

async function serve(handler: (req: Request, conn: Conn) => void | Promise<void>): Promise<FakeServer> {
  const server = await FakeServer.start(handler);
  servers.push(server);
  return server;
}

function client(server: FakeServer, options: Partial<ConstructorParameters<typeof Client>[0]> = {}): Client {
  return new Client({ baseUrl: server.url, token: TOKEN, ...options });
}

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("parsing", () => {
  test("results", () => {
    const r = parseResult(result({ future_field: 1 }));
    assert.equal(r.ok, true);
    assert.deepEqual([r.stdout, r.exitCode, r.stateLost, r.value], ["hi\n", 0, null, null]);
    const s = parseResult(
      result({ exit_code: 1, error: { type: "ZeroDivisionError", message: "division by zero", traceback: "T" }, state_lost: false }),
    );
    assert.equal(s.ok, false);
    assert.equal(s.error?.type, "ZeroDivisionError");
    assert.equal(s.stateLost, false);
    assert.equal(parseResult(result({ timed_out: true, exit_code: null, signal: 9 })).ok, false);
  });

  test("bad results", () => {
    for (const bad of [
      result({ exit_code: "0" }),
      result({ exit_code: true }),
      result({ exit_code: 1.5 }),
      result({ stdout: null }),
      result({ stdout_bytes: -1 }),
      result({ timed_out: 1 }),
      result({ value: 3 }),
      result({ error: { type: "X" } }),
      result({ state_lost: "no" }),
      [],
      "x",
      null,
    ]) {
      assert.throws(() => parseResult(bad), ResponseError, JSON.stringify(bad));
    }
  });

  test("polls and events", () => {
    const p = parsePoll({
      exec_id: "ex-2",
      state: "done",
      events: [
        { type: "stdout", data: "a" },
        { type: "omitted", bytes: 5 },
        { type: "stderr", data: "b" },
      ],
      next_cursor: 9,
      eof: true,
      result: result(),
    });
    assert.deepEqual(p.events, [
      { type: "stdout", data: "a" },
      { type: "omitted", bytes: 5 },
      { type: "stderr", data: "b" },
    ]);
    assert.throws(() => parseEvent({ type: "stdin", data: "x" }), ResponseError);
    assert.throws(() => parsePoll({ exec_id: "ex-2", state: "done", events: [], next_cursor: 0, eof: true, result: null }), ResponseError);
  });

  test("sandboxes", () => {
    assert.equal(parseSandbox(info()).readyMs, 7.5);
    assert.equal(parseSandbox(info()).egressId, "abababababababab");
    assert.throws(() => parseSandbox(info({ created_at: "1" })), ResponseError);
    assert.equal(parseSandbox(info()).usage, null);
    assert.equal(parseSandbox(info({ usage: counters({ cpu_ms: 7 }) })).usage?.cpuMs, 7);
    assert.throws(() => parseSandbox(info({ usage: counters({ cpu_ms: -1 }) })), ResponseError);
  });

  test("usage", () => {
    const u = parseUsage(tenantUsage());
    assert.deepEqual([u.tenant, u.periodStart, u.usage.cpuMs, u.exceeded], ["acme", 1000, 3, ["cpu"]]);
    assert.deepEqual([u.quotas.maxMemoryBytes, u.quotas.requestsPerSecond], [null, 2.5]);
    for (const bad of [tenantUsage({ exceeded: "cpu" }), tenantUsage({ period: null }), tenantUsage({ usage: {} })]) {
      assert.throws(() => parseUsage(bad), ResponseError);
    }
  });

  test("errors", () => {
    const e = apiError(409, Buffer.from('{"error": {"code": "busy", "message": "the sandbox is busy"}}'));
    assert.ok(e instanceof BusyError);
    assert.deepEqual([e.status, e.code, e.apiMessage], [409, "busy", "the sandbox is busy"]);
    const ended = apiError(410, Buffer.from('{"error": {"code": "sandbox_ended", "message": "the sandbox ended: idle"}}'));
    assert.ok(ended instanceof SandboxEndedError);
    assert.equal(ended.reason, "idle");
    assert.ok(apiError(401, Buffer.from('{"error":{"code":"unauthorized","message":"x"}}')) instanceof AuthenticationError);
    assert.ok(apiError(422, Buffer.from('{"error":{"code":"no_match","message":"x"}}')) instanceof EditError);
    assert.ok(apiError(429, Buffer.from('{"error":{"code":"tenant_limit","message":"x"}}')) instanceof LimitError);
    const rate = apiError(429, Buffer.from('{"error":{"code":"rate_limited","message":"x"}}'), 2);
    assert.ok(rate instanceof RateLimitError);
    assert.equal(rate.retryAfter, 2);
    const budget = apiError(429, Buffer.from('{"error":{"code":"budget_exceeded","message":"x"}}'), 60);
    assert.ok(budget instanceof BudgetExceededError && budget instanceof LimitError);
    assert.ok(apiError(429, Buffer.from('{"error":{"code":"memory_limit","message":"x"}}')) instanceof LimitError);
    assert.deepEqual([retryAfter("3"), retryAfter(" 10 "), retryAfter(null)], [3, 10, null]);
    for (const bad of ["-1", "1.5", "Wed, 21 Oct 2015 07:28:00 GMT", "9999999999"]) assert.equal(retryAfter(bad), null, bad);
    const proxy = apiError(502, Buffer.from("<html>bad gateway</html>".repeat(100)));
    assert.equal(proxy.constructor, APIError);
    assert.equal(proxy.code, "http_error");
    assert.ok(proxy.apiMessage.length <= 600);
  });
});

describe("retry rules", () => {
  test("delay", () => {
    let seed = 1;
    const random = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
    for (let attempt = 0; attempt < 40; attempt++) {
      const d = retry.delay(attempt, random);
      const full = Math.min(retry.MAX_DELAY, retry.BASE_DELAY * 2 ** attempt);
      assert.ok(full / 2 <= d && d <= full, `${attempt} ${d}`);
    }
  });

  test("rules", () => {
    const sent = new TransportError("x", { maybeSent: true });
    const unsent = new TransportError("x", { maybeSent: false });
    assert.equal(retry.transportRetry(unsent, false), true);
    assert.equal(retry.transportRetry(sent, false), false);
    assert.equal(retry.transportRetry(sent, true), true);
    assert.equal(retry.statusRetry(409, "busy", { busyWait: true, poll: false }), true);
    assert.equal(retry.statusRetry(409, "busy", { busyWait: false, poll: false }), false);
    assert.equal(retry.statusRetry(503, "template_not_ready", { busyWait: false, poll: false }), true);
    assert.equal(retry.statusRetry(429, "too_many_polls", { busyWait: false, poll: true }), true);
    assert.equal(retry.statusRetry(429, "too_many_polls", { busyWait: true, poll: false }), false);
    assert.equal(retry.statusRetry(429, "tenant_limit", { busyWait: true, poll: true }), false);
    assert.equal(retry.statusRetry(429, "rate_limited", { busyWait: false, poll: false }), true);
    assert.equal(retry.statusRetry(429, "budget_exceeded", { busyWait: true, poll: true }), false);
    assert.equal(retry.statusRetry(500, "internal", { busyWait: true, poll: true }), false);
  });
});

describe("configuration", () => {
  test("arguments", () => {
    for (const token of ["", "a b", "x\r\nHost: evil", "é"]) {
      assert.throws(() => new Client({ baseUrl: "http://127.0.0.1:1", token }), TypeError);
    }
    for (const baseUrl of ["ftp://x", "nope", "http://h/?q=1", "http://u:p@h/"]) {
      assert.throws(() => new Client({ baseUrl, token: TOKEN }), TypeError, baseUrl);
    }
    const c = new Client({ baseUrl: "http://127.0.0.1:1", token: TOKEN });
    assert.ok(!JSON.stringify(c).includes(TOKEN));
    assert.ok(!inspect(c, { showHidden: true, depth: 5 }).includes(TOKEN));
    assert.throws(() => c.sandbox("../etc"), TypeError);
    assert.throws(() => c.sandbox("sb-1?x=1"), TypeError);
  });
});

describe("against a fake server", () => {
  test("the token is sent and connections are reused", async () => {
    const server = await serve((req, conn) => {
      assert.equal(req.headers.authorization, `Bearer ${TOKEN}`);
      conn.json(200, { templates: [{ name: "python", ready: true }] });
    });
    const c = client(server);
    for (let i = 0; i < 6; i++) assert.equal((await c.templates())[0]?.name, "python");
    // Kept alive (undici may open a second one while the first is released).
    assert.ok(server.connections <= 2, String(server.connections));
  });

  test("errors carry status, code and message, not the token", async () => {
    const server = await serve((_req, conn) => conn.error(401, "unauthorized", "unknown token"));
    const error = await client(server).list().catch((e: unknown) => e);
    assert.ok(error instanceof AuthenticationError);
    assert.deepEqual([error.status, error.code, error.apiMessage], [401, "unauthorized", "unknown token"]);
    assert.ok(!String(error).includes(TOKEN));
    assert.ok(!String(error.stack).includes(TOKEN));
  });

  test("busy is waited out", async () => {
    let calls = 0;
    const server = await serve((_req, conn) => (++calls <= 2 ? conn.error(409, "busy", "busy") : conn.json(200, result())));
    assert.equal((await client(server).sandbox(SB).exec("echo hi")).stdout, "hi\n");
    assert.equal(calls, 3);
  });

  test("busy raises at once or at the deadline", async () => {
    let calls = 0;
    const server = await serve((_req, conn) => {
      calls++;
      conn.error(409, "busy", "busy");
    });
    await assert.rejects(client(server, { busy: "raise" }).sandbox(SB).exec("true"), BusyError);
    assert.equal(calls, 1);
    const started = Date.now();
    await assert.rejects(client(server, { busyTimeout: 0.4 }).sandbox(SB).writeFile("a", "x"), BusyError);
    assert.ok(Date.now() - started < 3000);
    assert.ok(calls > 2);
  });

  test("rate_limited waits Retry-After", async () => {
    const calls: number[] = [];
    const server = await serve((_req, conn) => {
      calls.push(Date.now());
      if (calls.length === 1) {
        conn.send(429, '{"error": {"code": "rate_limited", "message": "slow down"}}', { "Retry-After": "1", "Content-Type": "application/json" });
      } else {
        conn.json(200, { templates: [] });
      }
    });
    assert.deepEqual(await client(server).templates(), []);
    assert.equal(calls.length, 2);
    assert.ok((calls[1] ?? 0) - (calls[0] ?? 0) >= 900);
    const always = await serve((_req, conn) => conn.send(429, '{"error": {"code": "rate_limited", "message": "x"}}', { "Retry-After": "5" }));
    const error = await client(always, { busyTimeout: 1 }).templates().catch((e: unknown) => e);
    assert.ok(error instanceof RateLimitError);
    assert.equal(error.retryAfter, 5);
  });

  test("budget_exceeded is thrown at once", async () => {
    let calls = 0;
    const server = await serve((_req, conn) => {
      calls++;
      conn.send(429, '{"error": {"code": "budget_exceeded", "message": "used up"}}', { "Retry-After": "3600" });
    });
    const error = await client(server).create().catch((e: unknown) => e);
    assert.ok(error instanceof BudgetExceededError);
    assert.deepEqual([error.retryAfter, calls], [3600, 1]);
  });

  test("usage, and a delete accepted for later", async () => {
    const server = await serve((req, conn) => (req.path === "/v1/usage" ? conn.json(200, tenantUsage()) : conn.send(202)));
    const c = client(server);
    assert.equal((await c.usage()).quotas.cpuSecondsPerPeriod, 1.5);
    await c.delete(SB);
  });

  test("503 is retried", async () => {
    let calls = 0;
    const server = await serve((_req, conn) => (++calls === 1 ? conn.error(503, "template_not_ready", "try again") : conn.json(201, info())));
    const sandbox = await client(server).create();
    assert.equal(sandbox.id, SB);
    assert.equal(sandbox.info?.template, "python");
  });

  test("ambiguous failures never repeat execs or writes", async () => {
    const calls: string[] = [];
    const server = await serve((req, conn) => {
      calls.push(`${req.method} ${req.path}`);
      conn.drop();
    });
    const c = client(server, { retries: 3 });
    const sandbox = c.sandbox(SB);
    for (const call of [
      () => sandbox.exec("rm -rf /tmp/x"),
      () => sandbox.writeFile("a", "x"),
      () => sandbox.editFile("a", "x", "y"),
      () => sandbox.resetPython(),
      () => sandbox.stream("true"),
      () => c.create(),
    ]) {
      calls.length = 0;
      const error = await call().then(
        () => null,
        (e: unknown) => e,
      );
      assert.ok(error instanceof TransportError, String(error));
      assert.equal(error.maybeSent, true);
      assert.equal(calls.length, 1, calls.join());
    }
  });

  test("idempotent requests are retried", async () => {
    const calls: string[] = [];
    const server = await serve((req, conn) => {
      calls.push(req.method);
      if (calls.length % 2 === 1) conn.drop();
      else if (req.method === "DELETE") conn.error(404, "sandbox_not_found", "no such sandbox");
      else conn.send(200, Buffer.from([0, 255]), { "Content-Type": "application/octet-stream" });
    });
    const c = client(server);
    assert.deepEqual([...(await c.sandbox(SB).readFile("/bin/x"))], [0, 255]);
    await c.delete(SB);
    assert.deepEqual(calls, ["GET", "GET", "DELETE", "DELETE"]);
  });

  test("a delete of a missing sandbox throws", async () => {
    const server = await serve((_req, conn) => conn.error(404, "sandbox_not_found", "no such sandbox"));
    await assert.rejects(client(server).delete(SB), NotFoundError);
  });

  test("a refused connection was not sent", async () => {
    const port = await new Promise<number>((resolve) => {
      const s = net.createServer();
      s.listen(0, "127.0.0.1", () => {
        const p = (s.address() as net.AddressInfo).port;
        s.close(() => resolve(p));
      });
    });
    const error = await new Client({ baseUrl: `http://127.0.0.1:${port}`, token: TOKEN, retries: 1 })
      .sandbox(SB)
      .exec("true")
      .catch((e: unknown) => e);
    assert.ok(error instanceof TransportError);
    assert.equal(error.maybeSent, false);
  });

  test("a stalled server times out", async () => {
    const server = await serve(() => {});
    const started = Date.now();
    await assert.rejects(client(server, { timeout: 0.5, retries: 0 }).list(), RequestTimeoutError);
    assert.ok(Date.now() - started < 5000);
  });

  test("a trickling server times out at the deadline", async () => {
    const timers: NodeJS.Timeout[] = [];
    after(() => timers.forEach(clearInterval));
    const heads = await serve((_req, conn) => {
      conn.raw("HTTP/1.1 200 OK\r\n");
      timers.push(setInterval(() => conn.socket.writable && conn.raw("X-A: b\r\n"), 100));
    });
    let started = Date.now();
    await assert.rejects(client(heads, { timeout: 1, retries: 0 }).list(), RequestTimeoutError);
    assert.ok(Date.now() - started < 5000);
    const bodies = await serve((_req, conn) => {
      conn.raw("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n");
      timers.push(setInterval(() => conn.socket.writable && conn.raw("x"), 100));
    });
    started = Date.now();
    await assert.rejects(client(bodies, { timeout: 1, retries: 0 }).list(), RequestTimeoutError);
    assert.ok(Date.now() - started < 5000);
  });

  test("answers are bounded", async () => {
    const huge = await serve((_req, conn) => conn.raw("HTTP/1.1 200 OK\r\nContent-Length: 999999999999\r\n\r\n"));
    await assert.rejects(client(huge, { maxResponseBytes: 1 << 20 }).list(), ResponseError);
    const endless = await serve((_req, conn) => {
      conn.raw("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
      const chunk = Buffer.alloc(65536, 120);
      const write = () => {
        while (conn.socket.writable && conn.socket.write(chunk));
      };
      conn.socket.on("drain", write);
      write();
    });
    await assert.rejects(client(endless, { maxResponseBytes: 1 << 20 }).sandbox(SB).readFile("f"), ResponseError);
    const chunked = await serve((_req, conn) => {
      conn.raw("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
      const chunk = Buffer.concat([Buffer.from("10000\r\n"), Buffer.alloc(65536, 122), Buffer.from("\r\n")]);
      const write = () => {
        while (conn.socket.writable && conn.socket.write(chunk));
      };
      conn.socket.on("drain", write);
      write();
    });
    await assert.rejects(client(chunked, { maxResponseBytes: 1 << 20 }).sandbox(SB).readFile("f"), ResponseError);
  });

  test("malformed answers", async () => {
    for (const raw of ["HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{bad}"]) {
      const server = await serve((_req, conn) => {
        conn.raw(raw);
        conn.drop();
      });
      await assert.rejects(client(server).list(), ResponseError, raw);
    }
    const redirect = await serve((_req, conn) => conn.send(302, "", { Location: "http://evil.example/" }));
    await assert.rejects(client(redirect).list(), ResponseError);
    assert.equal(redirect.requests.length, 1);
  });

  test("large writes are refused before sending", async () => {
    const server = await serve((_req, conn) => conn.json(200, { bytes: 0 }));
    const error = await client(server)
      .sandbox(SB)
      .writeFile("big", new Uint8Array((16 << 20) + 1))
      .catch((e: unknown) => e);
    assert.ok(error instanceof LimitError);
    assert.equal(error.code, "too_large");
    assert.equal(server.requests.length, 0);
  });

  test("paths are encoded", async () => {
    const server = await serve((req, conn) => conn.json(200, { bytes: req.body.length }));
    await client(server).sandbox(SB).writeFile("/tmp/a b&c?d#e%", "é");
    const req = server.requests[0]!;
    assert.equal(req.query.get("path"), "/tmp/a b&c?d#e%");
    assert.deepEqual(req.body, Buffer.from("é"));
    assert.equal(req.method, "PUT");
  });

  test("withSandbox deletes even when the body throws", async () => {
    const server = await serve((req, conn) => (req.method === "POST" ? conn.json(201, info()) : conn.send(204)));
    await assert.rejects(
      client(server).withSandbox({}, async () => {
        throw new RangeError("boom");
      }),
      RangeError,
    );
    assert.deepEqual(
      server.requests.map((r) => r.method),
      ["POST", "DELETE"],
    );
    const gone = await serve((req, conn) =>
      req.method === "POST" ? conn.json(201, info()) : conn.error(410, "sandbox_ended", "the sandbox ended: idle"),
    );
    await client(gone).withSandbox({}, async () => {});
    {
      await using sandbox = await client(server).create();
      assert.equal(sandbox.id, SB);
    }
    assert.equal(server.requests.at(-1)?.method, "DELETE");
  });
});

describe("streams", () => {
  const output = ["one\n", "two\n", "three\n"];
  const full = output.join("");
  const ends = output.map((_, i) => output.slice(0, i + 1).join("").length);

  async function scripted(options: { finish: boolean; dropPoll?: number; startDelay?: number; together?: boolean }) {
    const state = { cancelled: false, wake: [] as (() => void)[], polls: [] as number[], started: [] as Record<string, unknown>[] };
    let pollNo = 0;
    const server = await serve(async (req, conn) => {
      const status = (extra: Record<string, unknown>) => ({ exec_id: "ex-7", kind: "command", started_at: 1, ...extra });
      if (req.method === "POST" && req.path.endsWith("/execs")) {
        state.started.push(JSON.parse(req.body.toString()) as Record<string, unknown>);
        if (options.startDelay) await pause(options.startDelay);
        conn.json(201, status({ state: "running", cancel_requested: false, result: null }));
      } else if (req.method === "POST" && req.path.endsWith("/cancel")) {
        state.cancelled = true;
        state.wake.forEach((w) => w());
        conn.json(200, status({ state: "done", cancel_requested: true, result: result({ exec_id: "ex-7", cancelled: true, signal: 9, exit_code: null }) }));
      } else {
        const cursor = Number(req.query.get("cursor"));
        state.polls.push(cursor);
        if (++pollNo === options.dropPoll) {
          conn.drop();
          return;
        }
        if (options.together && cursor === 0) {
          const events = output.map((data) => ({ type: "stdout", data }));
          conn.json(200, { exec_id: "ex-7", state: "running", events, next_cursor: full.length, eof: false, result: null });
          return;
        }
        const end = ends.find((e) => e > cursor);
        if (end !== undefined) {
          conn.json(200, { exec_id: "ex-7", state: "running", events: [{ type: "stdout", data: full.slice(cursor, end) }], next_cursor: end, eof: false, result: null });
          return;
        }
        if (!options.finish && !state.cancelled) {
          await new Promise<void>((resolve) => {
            state.wake.push(resolve);
            setTimeout(resolve, 2000);
          });
        }
        if (options.finish || state.cancelled) {
          conn.json(200, { exec_id: "ex-7", state: "done", events: [], next_cursor: cursor, eof: true, result: result({ exec_id: "ex-7", stdout: full, cancelled: state.cancelled }) });
        } else {
          conn.json(200, { exec_id: "ex-7", state: "running", events: [], next_cursor: cursor, eof: false, result: null });
        }
      }
    });
    return { c: client(server), state };
  }

  test("events in order, then the result", async () => {
    const { c, state } = await scripted({ finish: true });
    const ex = await c.sandbox(SB).stream("x");
    const events: StreamEvent[] = [];
    for await (const e of ex) events.push(e);
    assert.deepEqual(events.slice(0, 3), output.map((data) => ({ type: "stdout", data })));
    const last = events.at(-1);
    assert.equal(last?.type, "result");
    assert.equal(ex.result?.stdout, full);
    assert.deepEqual(state.polls, [0, 4, 8, 14]);
  });

  test("resumes after a dropped connection", async () => {
    const { c, state } = await scripted({ finish: true, dropPoll: 2 });
    const ex = await c.sandbox(SB).stream("x");
    const texts: string[] = [];
    for await (const e of ex) if (e.type === "stdout") texts.push(e.data);
    assert.equal(texts.join(""), full);
    assert.deepEqual(state.polls.slice(1, 3), [4, 4]);
  });

  test("cancel from another task wakes the poll", async () => {
    const { c } = await scripted({ finish: false });
    const ex = await c.sandbox(SB).stream("sleep 100");
    const events: StreamEvent[] = [];
    const following = (async () => {
      for await (const e of ex) events.push(e);
    })();
    await pause(200);
    const cancelled = await ex.cancel();
    assert.equal(cancelled?.cancelled, true);
    await following;
    assert.equal(ex.result?.cancelled, true);
    assert.equal(events.at(-1)?.type, "result");
  });

  test("an AbortSignal cancels the exec and rejects", async () => {
    const { c, state } = await scripted({ finish: false });
    const controller = new AbortController();
    const ex = await c.sandbox(SB).stream("sleep 100", { signal: controller.signal });
    const waiting = ex.wait();
    await pause(200);
    controller.abort(new Error("enough"));
    await assert.rejects(waiting, AbortedError);
    await pause(100);
    assert.equal(state.cancelled, true);
    // exec() with a signal goes the same way.
    const second = await scripted({ finish: false });
    const again = new AbortController();
    const running = second.c.sandbox(SB).exec("sleep 100", { signal: again.signal });
    setTimeout(() => again.abort(), 200);
    await assert.rejects(running, AbortedError);
    await pause(100);
    assert.equal(second.state.cancelled, true);
  });

  test("an abort while the exec is being started still cancels it", async () => {
    const { c, state } = await scripted({ finish: false, startDelay: 300 });
    const controller = new AbortController();
    const running = c.sandbox(SB).exec("sleep 100", { signal: controller.signal });
    setTimeout(() => controller.abort(), 100);
    await assert.rejects(running, AbortedError);
    await pause(100);
    assert.equal(state.started.length, 1);
    assert.equal(state.cancelled, true);
    // Aborted before anything was sent: nothing is started.
    const before = new AbortController();
    before.abort();
    await assert.rejects(c.sandbox(SB).exec("sleep 100", { signal: before.signal }), AbortedError);
    assert.equal(state.started.length, 1);
  });

  test("an exec too long for one request is started and followed", async () => {
    const { c, state } = await scripted({ finish: true });
    const r = await c.sandbox(SB).exec("make", { timeout: 900 });
    assert.equal(r.stdout, full);
    assert.deepEqual(state.started, [{ command: "make", timeout: 900 }]);
    assert.ok(state.polls.length > 0);
  });

  test("a loop that stops early loses no event", async () => {
    const { c } = await scripted({ finish: true, together: true });
    const ex = await c.sandbox(SB).stream("x");
    const texts: string[] = [];
    for await (const e of ex) {
      if (e.type === "stdout") texts.push(e.data);
      break;
    }
    for await (const e of ex) if (e.type === "stdout") texts.push(e.data);
    assert.deepEqual(texts, output);
    assert.equal(ex.result?.stdout, full);
  });

  test("an abort after the end cancels nothing", async () => {
    const { c, state } = await scripted({ finish: true });
    const controller = new AbortController();
    const r = await c.sandbox(SB).exec("x", { signal: controller.signal });
    assert.equal(r.stdout, full);
    controller.abort();
    await pause(100);
    assert.equal(state.cancelled, false);
  });

  test("close cuts a poll off without cancelling", async () => {
    const { c, state } = await scripted({ finish: false });
    const ex = await c.sandbox(SB).stream("sleep 100");
    const following = (async () => {
      for await (const _ of ex) {
        // keep going
      }
    })();
    await pause(200);
    ex.close();
    await following;
    assert.equal(ex.result, null);
    assert.equal(state.cancelled, false);
  });

  test("await using cancels what is left", async () => {
    const { c, state } = await scripted({ finish: false });
    {
      await using ex = await c.sandbox(SB).stream("sleep 100");
      for await (const _ of ex) break;
    }
    assert.equal(state.cancelled, true);
  });

  test("a cursor moving backwards is refused", async () => {
    const server = await serve((req, conn) => {
      if (req.method === "POST") {
        conn.json(201, { exec_id: "ex-1", kind: "command", state: "running", started_at: 1, cancel_requested: false, result: null });
      } else {
        const next = req.query.get("cursor") === "0" ? 3 : 1;
        conn.json(200, { exec_id: "ex-1", state: "running", events: [{ type: "stdout", data: "abc" }], next_cursor: next, eof: false, result: null });
      }
    });
    const ex = await client(server).sandbox(SB).stream("x");
    await assert.rejects(ex.wait(), ResponseError);
  });

  test("too many polls is waited out", async () => {
    let polls = 0;
    const server = await serve((req, conn) => {
      if (req.method === "POST") {
        conn.json(201, { exec_id: "ex-1", kind: "command", state: "running", started_at: 1, cancel_requested: false, result: null });
      } else if (polls++ === 0) {
        conn.error(429, "too_many_polls", "four polls wait already");
      } else {
        conn.json(200, { exec_id: "ex-1", state: "done", events: [], next_cursor: 0, eof: true, result: result({ exec_id: "ex-1" }) });
      }
    });
    assert.equal((await (await client(server).sandbox(SB).stream("x")).wait()).exitCode, 0);
  });
});
