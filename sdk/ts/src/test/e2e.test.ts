/**
 * End-to-end tests against a real plane, the same ground as the Python
 * SDK's: `kernel/api/tests/sdk.rs` starts one and passes it in
 * `HELLOVM_TEST_URL`, `HELLOVM_TEST_TOKEN`, `HELLOVM_TEST_TEMPLATE`,
 * `HELLOVM_TEST_TOKEN_B`, `HELLOVM_TEST_TEMPLATE_B`, `HELLOVM_TEST_INGRESS`. Skipped without them
 * (a failure with `HELLOVM_REQUIRE_E2E=1`).
 */

import assert from "node:assert/strict";
import * as net from "node:net";
import { after, before, describe, test } from "node:test";

import {
  APIError,
  AuthenticationError,
  BusyError,
  Client,
  EditError,
  LimitError,
  NotFoundError,
  type Sandbox,
  SandboxEndedError,
  type StreamEvent,
} from "../index.js";

const URL_ = process.env.HELLOVM_TEST_URL ?? "";
const TOKEN = process.env.HELLOVM_TEST_TOKEN ?? "";
const TEMPLATE = process.env.HELLOVM_TEST_TEMPLATE ?? "python";
const TOKEN_B = process.env.HELLOVM_TEST_TOKEN_B ?? "";
const TEMPLATE_B = process.env.HELLOVM_TEST_TEMPLATE_B ?? TEMPLATE;
const INGRESS = process.env.HELLOVM_TEST_INGRESS ?? "";
const skip = !URL_ || !TOKEN;
if (skip && process.env.HELLOVM_REQUIRE_E2E === "1") {
  throw new Error("required e2e dependency missing: HELLOVM_TEST_URL (start a plane, see kernel/api/tests/sdk.rs)");
}

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function eventually(what: string, check: () => Promise<boolean>, limitMs = 30000): Promise<void> {
  const deadline = Date.now() + limitMs;
  while (!(await check())) {
    if (Date.now() > deadline) throw new Error(`timed out: ${what}`);
    await pause(50);
  }
}

/** A TCP proxy to the API whose connections can all be cut at once. */
class DroppingProxy {
  readonly #sockets = new Set<net.Socket>();
  readonly #server: net.Server;
  url = "";
  cuts = 0;

  constructor(target: string) {
    const { hostname, port } = new URL(target);
    this.#server = net.createServer((client) => {
      const upstream = net.connect(Number(port), hostname);
      for (const s of [client, upstream]) {
        this.#sockets.add(s);
        s.on("error", () => {});
        s.on("close", () => this.#sockets.delete(s));
      }
      client.pipe(upstream).pipe(client);
    });
  }

  async start(): Promise<this> {
    await new Promise<void>((resolve) => this.#server.listen(0, "127.0.0.1", resolve));
    this.url = `http://127.0.0.1:${(this.#server.address() as net.AddressInfo).port}`;
    return this;
  }

  cut(): void {
    this.cuts++;
    for (const s of this.#sockets) s.destroy();
  }

  async close(): Promise<void> {
    this.cut();
    await new Promise<void>((resolve) => this.#server.close(() => resolve()));
  }
}

describe("against a real plane", { skip: skip ? "set HELLOVM_TEST_URL and HELLOVM_TEST_TOKEN (a running plane)" : false }, () => {
  let client: Client;
  let shared: Sandbox;
  const cleanups: (() => Promise<unknown>)[] = [];

  before(async () => {
    client = new Client({ baseUrl: URL_, token: TOKEN });
    shared = await client.create({ template: TEMPLATE });
  });

  after(async () => {
    for (const c of cleanups.reverse()) await c().catch(() => {});
    await shared.delete();
  });

  async function sandbox(options: { lifetime?: number } = {}): Promise<Sandbox> {
    const sb = await client.create({ template: TEMPLATE, ...options });
    cleanups.push(() => sb.dispose(false));
    return sb;
  }

  test("templates, create, get, list, delete", async () => {
    assert.ok((await client.templates()).some((t) => t.name === TEMPLATE && t.ready));
    let id = "";
    await client.withSandbox({ template: TEMPLATE, idleTimeout: 300 }, async (sb) => {
      id = sb.id;
      assert.equal(sb.info?.template, TEMPLATE);
      assert.equal(sb.info?.idleTimeout, 300);
      assert.ok((await client.list()).some((s) => s.id === sb.id));
      const got = await client.get(sb.id);
      assert.equal(got.info?.egressId, sb.id.slice(3, 19));
      assert.ok((await sb.refresh()).memoryLimitBytes > 0);
      assert.ok((await sb.refresh()).usage !== null);
      const usage = await client.usage();
      assert.ok(usage.sandboxes >= 1 && usage.periodEnd > usage.periodStart && usage.quotas.maxSandboxes > 0);
    });
    const error = await client.get(id).catch((e: unknown) => e);
    assert.ok(error instanceof NotFoundError);
    assert.equal(error.code, "sandbox_not_found");
    await assert.rejects(client.delete(id), NotFoundError);
  });

  test("withSandbox and await using delete even when the body throws", async () => {
    let id = "";
    await assert.rejects(
      client.withSandbox({ template: TEMPLATE }, async (sb) => {
        id = sb.id;
        await sb.exec("true");
        throw new RangeError("boom");
      }),
      RangeError,
    );
    await assert.rejects(client.get(id), NotFoundError);
    await assert.rejects(
      (async () => {
        await using sb = await client.create({ template: TEMPLATE });
        id = sb.id;
        throw new RangeError("boom");
      })(),
      RangeError,
    );
    await assert.rejects(client.get(id), NotFoundError);
  });

  test("authentication failure", async () => {
    const error = await new Client({ baseUrl: URL_, token: "not-a-token-0123456789abcdef" }).list().catch((e: unknown) => e);
    assert.ok(error instanceof AuthenticationError);
    assert.deepEqual([error.status, error.code], [401, "unauthorized"]);
    assert.ok(!String(error).includes("not-a-token"));
  });

  test("a second tenant sees nothing", { skip: !TOKEN_B }, async () => {
    const other = new Client({ baseUrl: URL_, token: TOKEN_B });
    assert.ok(!(await other.list()).some((s) => s.id === shared.id));
    const theirs = other.sandbox(shared.id);
    for (const call of [
      () => theirs.refresh(),
      () => theirs.exec("true"),
      () => theirs.readFile("/etc/hostname"),
      () => theirs.writeFile("x", "y"),
      () => theirs.run("1"),
      () => theirs.resetPython(),
      () => theirs.latestExec(),
      () => theirs.stream("true"),
      () => theirs.delete(),
    ]) {
      const error = await call().catch((e: unknown) => e);
      assert.ok(error instanceof NotFoundError, String(error));
      assert.equal(error.code, "sandbox_not_found");
    }
    assert.equal((await shared.exec("echo still here")).stdout, "still here\n");
    await other.withSandbox({ template: TEMPLATE_B }, async (mine) => {
      assert.ok(!(await client.list()).some((s) => s.id === mine.id));
    });
  });

  test("an ended sandbox says why", async () => {
    const sb = await sandbox({ lifetime: 1 });
    let ended: SandboxEndedError | undefined;
    await eventually("the sandbox did not end", async () => {
      try {
        await sb.refresh();
        return false;
      } catch (error) {
        if (!(error instanceof SandboxEndedError)) throw error;
        ended = error;
        return true;
      }
    });
    assert.deepEqual([ended?.status, ended?.code], [410, "sandbox_ended"]);
    assert.match(ended?.reason ?? "", /lifetime/);
    await assert.rejects(sb.exec("true"), SandboxEndedError);
  });

  test("exec", async () => {
    let r = await shared.exec("echo out; echo err >&2; exit 3");
    assert.deepEqual([r.stdout, r.stderr, r.exitCode, r.signal, r.ok], ["out\n", "err\n", 3, null, false]);
    assert.match(r.execId, /^ex-\d+$/);
    assert.equal((await shared.exec("true")).ok, true);
    r = await shared.exec("cat; pwd; echo $GREETING", { stdin: "from stdin\n", cwd: "/tmp", env: { GREETING: "hello" } });
    assert.equal(r.stdout, "from stdin\n/tmp\nhello\n");
    const missing = await shared.exec("true", { cwd: "/no/such/dir" }).catch((e: unknown) => e);
    assert.ok(missing instanceof NotFoundError);
    assert.equal(missing.code, "not_found");
    const bad = await shared.exec("true", { timeout: -1 }).catch((e: unknown) => e);
    assert.ok(bad instanceof APIError);
    assert.deepEqual([bad.status, bad.code], [400, "bad_request"]);
  });

  test("ingress: expose a server, the token, public, unexpose", { skip: !INGRESS }, async () => {
    await client.withSandbox({ template: TEMPLATE }, async (sb) => {
      await sb.writeFile("/tmp/www/index.html", "hello from the sandbox\n");
      await sb.exec("cd /tmp/www && nohup python3 -m http.server 8000 --bind 0.0.0.0 >/dev/null 2>&1 &");
      assert.deepEqual((await sb.ingress()).ports, []);
      const port = await sb.expose(8000);
      assert.equal(port.public, false);
      const host = new URL(port.url).hostname;
      assert.ok(host.startsWith(`8000-${sb.id}.`), port.url);
      const token = (await sb.ingress()).token;
      const [addr, p] = [INGRESS.slice(0, INGRESS.lastIndexOf(":")), Number(INGRESS.slice(INGRESS.lastIndexOf(":") + 1))];
      const get = (headers: string) =>
        new Promise<[number, string]>((resolve, reject) => {
          const sock = net.connect(p, addr);
          const chunks: Buffer[] = [];
          sock.on("data", (d) => chunks.push(d));
          sock.on("error", reject);
          sock.on("end", () => {
            const text = Buffer.concat(chunks).toString();
            resolve([Number(text.slice(9, 12)), text.slice(text.indexOf("\r\n\r\n") + 4)]);
          });
          sock.write(`GET /index.html HTTP/1.1\r\nHost: ${host}\r\n${headers}\r\n`);
        });
      const auth = `X-Hellovm-Ingress-Token: ${token}\r\n`;
      await eventually("the server answers", async () => (await get(auth))[0] === 200);
      assert.deepEqual(await get(auth), [200, "hello from the sandbox\n"]);
      assert.equal((await get(""))[0], 404);
      assert.equal((await sb.expose(8000, { public: true })).public, true);
      assert.equal((await get(""))[0], 200);
      const rotated = await sb.rotateIngressToken();
      assert.notEqual(rotated, token);
      await sb.unexpose(8000);
      assert.equal((await get(`X-Hellovm-Ingress-Token: ${rotated}\r\n`))[0], 404);
      await eventually("ingress metered", async () => ((await sb.refresh()).usage?.ingressSentBytes ?? 0) > 0, 10000);
    });
  });

  test("exec timeout", async () => {
    const started = Date.now();
    const r = await shared.exec("echo before; sleep 30; echo after", { timeout: 1 });
    assert.ok(Date.now() - started < 20000);
    assert.equal(r.timedOut, true);
    assert.deepEqual([r.signal, r.exitCode, r.stdout], [9, null, "before\n"]);
  });

  test("exec truncation", async () => {
    const r = await shared.exec("head -c 100000 /dev/zero | tr '\\0' a; echo; seq 1 3 >&2", { maxOutput: 1024 });
    assert.equal(r.stdoutTruncated, true);
    assert.equal(r.stderrTruncated, false);
    assert.equal(r.stdoutBytes, 100001);
    assert.match(r.stdout, /bytes omitted/);
    assert.ok(r.stdout.length < 1200);
    assert.ok(r.stdout.startsWith("a".repeat(400)));
    assert.equal(r.stderr, "1\n2\n3\n");
  });

  test("python in a fresh fork", async () => {
    let r = await shared.python("import json, sys\nprint(json.dumps({'a': 1}))\nsys.exit(4)");
    assert.deepEqual([r.stdout, r.exitCode], ['{"a": 1}\n', 4]);
    await shared.python("x = 1");
    r = await shared.python("print(x)");
    assert.equal(r.exitCode, 1);
    assert.match(r.stderr, /NameError/);
  });

  test("the stateful interpreter", async () => {
    const sb = await sandbox();
    assert.equal((await sb.run("import math\nx = 20")).value, null);
    let r = await sb.run("x += 1\nprint('side', end='')\nmath.floor(x * 2.5)");
    assert.deepEqual([r.value, r.stdout, r.exitCode, r.stateLost], ["52", "side", 0, false]);
    r = await sb.run("def f():\n    return 1 / 0\nf()");
    assert.deepEqual([r.error?.type, r.exitCode], ["ZeroDivisionError", 1]);
    assert.match(r.error?.message ?? "", /division by zero/);
    assert.match(r.error?.traceback ?? "", /in f/);
    assert.equal((await sb.run("x")).value, "21");
    assert.equal((await sb.run("input()", { stdin: "typed\n" })).value, "'typed'");
    assert.equal(await sb.resetPython(), true);
    assert.equal((await sb.run("x")).error?.type, "NameError");
  });

  test("stateful state lost, and a timeout", async () => {
    const sb = await sandbox();
    await sb.run("y = 5");
    let r = await sb.run("import os\nos._exit(7)");
    assert.equal(r.stateLost, true);
    assert.equal(r.error?.type, "InterpreterExited");
    assert.equal((await sb.run("y")).error?.type, "NameError");
    await sb.run("z = 9");
    r = await sb.run("import time\ntime.sleep(60)", { timeout: 1 });
    assert.equal(r.timedOut, true);
    // Interrupted (state kept), or on a slow machine killed after the 2 s grace.
    if (r.stateLost) assert.equal(r.error?.type, "InterpreterKilled");
    else {
      assert.equal(r.error?.type, "KeyboardInterrupt");
      assert.equal((await sb.run("z")).value, "9");
    }
  });

  test("stream: output before the end, in order", async () => {
    const sb = await sandbox();
    const ex = await sb.stream("for i in 1 2 3; do echo out$i; echo err$i >&2; sleep 0.3; done");
    const events: StreamEvent[] = [];
    let seenBeforeEnd = false;
    for await (const e of ex) {
      events.push(e);
      if (e.type === "stdout" && e.data.startsWith("out1") && ex.result === null) {
        seenBeforeEnd = (await sb.latestExec())?.state === "running";
      }
    }
    assert.equal(seenBeforeEnd, true);
    const last = events.at(-1);
    assert.equal(last?.type, "result");
    const text = (type: string) =>
      events
        .filter((e) => e.type === type)
        .map((e) => (e as { data: string }).data)
        .join("");
    assert.deepEqual([text("stdout"), text("stderr")], ["out1\nout2\nout3\n", "err1\nerr2\nerr3\n"]);
    const joined = events.map((e) => ("data" in e ? e.data : "")).join("");
    assert.ok(joined.indexOf("out1") < joined.indexOf("out2"));
    assert.ok(joined.indexOf("err1") < joined.indexOf("out2"));
    assert.equal(ex.cursor, "out1\nerr1\nout2\nerr2\nout3\nerr3\n".length);
  });

  test("stream resumes after a dropped connection", async () => {
    const sb = await sandbox();
    const proxy = await new DroppingProxy(URL_).start();
    cleanups.push(() => proxy.close());
    const through = new Client({ baseUrl: proxy.url, token: TOKEN });
    const ex = await through.sandbox(sb.id).stream("echo first; sleep 1; echo second; sleep 1; echo third");
    const texts: string[] = [];
    for await (const e of ex) {
      if (e.type === "stdout") {
        texts.push(e.data);
        if (e.data === "first\n") proxy.cut();
      }
    }
    assert.equal(texts.join(""), "first\nsecond\nthird\n");
    assert.equal(ex.result?.exitCode, 0);
    assert.ok(proxy.cuts >= 1);
  });

  test("stream cancelled from another task, and by an AbortSignal", async () => {
    const sb = await sandbox();
    const ex = await sb.stream("echo started; sleep 60; echo never");
    const events: StreamEvent[] = [];
    let started!: () => void;
    const startedP = new Promise<void>((r) => (started = r));
    const following = (async () => {
      for await (const e of ex) {
        events.push(e);
        started();
      }
    })();
    await startedP;
    const begun = Date.now();
    await ex.cancel();
    await following;
    assert.ok(Date.now() - begun < 15000);
    assert.equal(ex.result?.cancelled, true);
    assert.equal(ex.result?.signal, 9);
    assert.ok(!ex.result?.stdout.includes("never"));
    assert.equal(events.at(-1)?.type, "result");
    assert.equal((await sb.exec("echo free")).stdout, "free\n");

    const controller = new AbortController();
    const running = sb.exec("sleep 60", { signal: controller.signal });
    await eventually("the exec did not start", async () => (await sb.latestExec())?.state === "running");
    controller.abort();
    await assert.rejects(running, { name: "AbortedError" });
    await eventually("the aborted exec was not cancelled", async () => (await sb.latestExec())?.result?.cancelled === true);
    assert.equal((await sb.exec("echo free again", { timeout: 10 })).stdout, "free again\n");
  });

  test("leaving a stream early cancels it", async () => {
    const sb = await sandbox();
    let id = "";
    {
      await using ex = await sb.stream("echo go; sleep 60");
      id = ex.id;
      for await (const _ of ex) break;
    }
    assert.equal((await sb.latestExec())?.execId, id);
    assert.equal((await sb.exec("echo next", { timeout: 10 })).stdout, "next\n");
  });

  test("stateful streams and omitted output", async () => {
    const sb = await sandbox();
    const r = await (await sb.streamPython("v = 6\nprint('x')\nv * 7", { stateful: true })).wait();
    assert.deepEqual([r.value, r.stdout], ["42", "x\n"]);
    const ex = await sb.stream("head -c 3000000 /dev/zero | tr '\\0' b", { maxOutput: 1024, pollBytes: 1024 });
    await pause(500);
    const events: StreamEvent[] = [];
    for await (const e of ex) events.push(e);
    assert.equal(ex.result?.stdoutBytes, 3000000);
    assert.ok(events.some((e) => e.type === "omitted"));
  });

  test("busy: raise, and wait", async () => {
    const sb = await sandbox();
    const raising = new Client({ baseUrl: URL_, token: TOKEN, busy: "raise" });
    const holder = sb.exec("sleep 2; echo held");
    await eventually("the first exec did not start", async () => (await sb.latestExec())?.state === "running");
    const error = await raising.sandbox(sb.id).exec("echo now").catch((e: unknown) => e);
    assert.ok(error instanceof BusyError);
    assert.deepEqual([error.status, error.code], [409, "busy"]);
    await assert.rejects(raising.sandbox(sb.id).writeFile("f", "x"), BusyError);
    assert.equal((await sb.exec("echo after")).stdout, "after\n");
    assert.equal((await holder).stdout, "held\n");
  });

  test("files", async () => {
    const data = new Uint8Array(256 * 300).map((_, i) => i % 256);
    assert.equal(await shared.writeFile("/tmp/dir/sub/bin", data), data.length);
    assert.deepEqual(await shared.readFile("/tmp/dir/sub/bin"), data);
    const text = "hello wörld\nhello again\n";
    assert.equal(await shared.writeFile("notes.txt", text), new TextEncoder().encode(text).length);
    assert.equal(await shared.readText("notes.txt"), text);
    assert.equal((await shared.exec("cat notes.txt")).stdout, text);
    assert.equal(await shared.editFile("notes.txt", "wörld", "there"), 1);
    let error = await shared.editFile("notes.txt", "hello", "bye").catch((e: unknown) => e);
    assert.ok(error instanceof EditError);
    assert.equal(error.code, "ambiguous");
    assert.equal(await shared.editFile("notes.txt", "hello", "bye", { replaceAll: true }), 2);
    assert.equal(await shared.readText("notes.txt"), "bye there\nbye again\n");
    error = await shared.editFile("notes.txt", "absent", "x").catch((e: unknown) => e);
    assert.ok(error instanceof EditError);
    assert.equal(error.code, "no_match");
    error = await shared.editFile("/tmp/dir/sub/bin", "a", "b").catch((e: unknown) => e);
    assert.ok(error instanceof APIError);
    assert.equal(error.code, "not_text");
    error = await shared.readFile("/no/such/file").catch((e: unknown) => e);
    assert.ok(error instanceof NotFoundError);
    assert.equal(error.code, "not_found");
    error = await shared.readFile("/tmp/dir").catch((e: unknown) => e);
    assert.ok(error instanceof APIError);
    assert.deepEqual([error.status, error.code], [400, "is_directory"]);
    await assert.rejects(shared.writeFile("big", new Uint8Array((16 << 20) + 1)), LimitError);
    assert.equal(await shared.writeFile("/tmp/empty", new Uint8Array()), 0);
    assert.equal((await shared.readFile("/tmp/empty")).length, 0);
  });
});
