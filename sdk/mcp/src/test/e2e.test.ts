/**
 * The MCP server against a real plane (see `kernel/api/tests/sdk.rs`):
 * every tool's success and failure, truncation, a timeout, cancellation,
 * a sandbox that ended, the sandbox deleted at exit, and the token
 * nowhere in what the server wrote.
 */

import assert from "node:assert/strict";
import { after, describe, test } from "node:test";

import { Client } from "hellovm";

import { McpProcess, text } from "./client.js";

const URL_ = process.env.HELLOVM_TEST_URL ?? "";
const TOKEN = process.env.HELLOVM_TEST_TOKEN ?? "";
const TEMPLATE = process.env.HELLOVM_TEST_TEMPLATE ?? "python";
const skip = !URL_ || !TOKEN;
if (skip && process.env.HELLOVM_REQUIRE_E2E === "1") {
  throw new Error("required e2e dependency missing: HELLOVM_TEST_URL (start a plane, see kernel/api/tests/sdk.rs)");
}

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));
const procs: McpProcess[] = [];

function start(env: Record<string, string> = {}, era: "modern" | "legacy" = "modern"): McpProcess {
  const p = new McpProcess(
    { HELLOVM_URL: URL_, HELLOVM_TOKEN: TOKEN, HELLOVM_TEMPLATE: TEMPLATE, HELLOVM_MCP_MAX_OUTPUT: "1024", ...env },
    era,
  );
  procs.push(p);
  return p;
}

function noToken(p: McpProcess): void {
  assert.ok(!p.stdout.includes(TOKEN), "the token is in the server's stdout");
  assert.ok(!p.stderr.includes(TOKEN), "the token is in the server's stderr");
}

describe("the MCP server against a real plane", { skip: skip ? "set HELLOVM_TEST_URL and HELLOVM_TEST_TOKEN (a running plane)" : false }, () => {
  const client = new Client({ baseUrl: URL_, token: TOKEN });
  after(async () => {
    for (const p of procs) await p.close().catch(() => {});
  });

  async function sandboxIds(): Promise<string[]> {
    return (await client.list()).map((s) => s.id);
  }

  test("every tool, in one session, and the sandbox deleted at exit", async () => {
    const before = await sandboxIds();
    const p = start();
    await p.request("server/discover");
    assert.deepEqual(await sandboxIds(), before, "no sandbox before the first call");

    let r = await p.call("exec", { command: "echo hello; echo oops >&2; exit 3" });
    assert.equal(r.isError, undefined);
    assert.equal(text(r), "Exit code: 3\n--- stdout ---\nhello\n--- end of stdout ---\n--- stderr ---\noops\n--- end of stderr ---");
    const created = (await sandboxIds()).filter((id) => !before.includes(id));
    assert.equal(created.length, 1, "one sandbox, made on first use");

    r = await p.call("exec", { command: "pwd", cwd: "/tmp" });
    assert.match(text(r), /^Exit code: 0\n--- stdout ---\n\/tmp\n/);
    r = await p.call("exec", { command: "true", cwd: "/no/such/dir" });
    assert.equal(r.isError, true);
    assert.match(text(r), /^Error \(404 not_found\)/);

    // Truncation, by the API's rule (HELLOVM_MCP_MAX_OUTPUT=1024 here).
    r = await p.call("exec", { command: "seq 1 20000" });
    assert.match(text(r), /--- stdout \(108894 bytes in all, too long: only its start and end are shown/);
    assert.match(text(r), /\n1\n2\n3\n/);
    assert.match(text(r), /\[\.\.\. 107870 bytes omitted \.\.\.\]/);
    assert.match(text(r), /\n20000\n--- end of stdout ---/);

    // A timeout.
    const began = Date.now();
    r = await p.call("exec", { command: "echo started; sleep 30", timeout: 1 });
    assert.ok(Date.now() - began < 20000);
    assert.match(text(r), /^Timed out after 1 s: the command was killed \(signal 9\)\.\n--- stdout ---\nstarted\n/);

    // Python: state, values, exceptions, restart.
    r = await p.call("python", { code: "import math\nx = 41" });
    assert.equal(text(r), "Done (no value).");
    r = await p.call("python", { code: "x += 1\nprint('side')\nx" });
    assert.equal(text(r), "Value: 42\n--- stdout ---\nside\n--- end of stdout ---");
    r = await p.call("python", { code: "def f():\n    return 1 / 0\nf()" });
    assert.equal(r.isError, undefined);
    assert.match(text(r), /^Raised ZeroDivisionError: division by zero\nTraceback \(most recent call last\):[^]*in f/);
    r = await p.call("python", { code: "x", restart: true });
    assert.match(text(r), /^Raised NameError/);
    r = await p.call("python", { code: "import time\ntime.sleep(30)", timeout: 1 });
    assert.match(text(r), /^Timed out after 1 s and was interrupted\.\n/);
    r = await p.call("python", { code: "import os\nos._exit(3)" });
    assert.match(text(r), /state was lost/);

    // Files.
    r = await p.call("write_file", { path: "notes/a.txt", content: "alpha\nbeta\nbeta\n" });
    assert.equal(text(r), "Wrote 16 bytes to notes/a.txt.");
    r = await p.call("read_file", { path: "notes/a.txt" });
    assert.equal(text(r), "alpha\nbeta\nbeta\n");
    r = await p.call("edit_file", { path: "notes/a.txt", old_text: "alpha", new_text: "gamma" });
    assert.equal(text(r), "Replaced 1 occurrence in notes/a.txt.");
    r = await p.call("edit_file", { path: "notes/a.txt", old_text: "beta", new_text: "delta" });
    assert.equal(r.isError, true);
    assert.match(text(r), /^Error \(422 ambiguous\)/);
    r = await p.call("edit_file", { path: "notes/a.txt", old_text: "beta", new_text: "delta", replace_all: true });
    assert.equal(text(r), "Replaced 2 occurrences in notes/a.txt.");
    r = await p.call("edit_file", { path: "notes/a.txt", old_text: "absent", new_text: "x" });
    assert.match(text(r), /^Error \(422 no_match\)/);
    r = await p.call("read_file", { path: "/no/such/file" });
    assert.equal(r.isError, true);
    assert.match(text(r), /^Error \(404 not_found\)/);
    await p.call("exec", { command: "head -c 300 /dev/urandom > /tmp/bin; seq 1 5000 > /tmp/long" });
    assert.match(text(await p.call("read_file", { path: "/tmp/bin" })), /binary file \(300 bytes/);
    r = await p.call("read_file", { path: "/tmp/long" });
    assert.match(text(r), /^1\n2\n/);
    assert.match(text(r), /\/tmp\/long is 23893 bytes, too long/);
    assert.match(text((await p.call("read_file", { path: "/tmp" }))), /^Error \(400 is_directory\)/);

    // Reset: a new, empty sandbox.
    r = await p.call("reset_sandbox");
    assert.match(text(r), /reset/);
    assert.ok(!(await sandboxIds()).includes(created[0]!));
    r = await p.call("read_file", { path: "notes/a.txt" });
    assert.match(text(r), /^Error \(404 not_found\)/);
    const second = (await sandboxIds()).filter((id) => !before.includes(id));
    assert.equal(second.length, 1);

    assert.equal(await p.close(), 0);
    assert.ok(!(await sandboxIds()).includes(second[0]!), "the sandbox is deleted when the server exits");
    noToken(p);
  });

  test("the legacy handshake works end to end", async () => {
    const p = start({}, "legacy");
    await p.initialize();
    assert.match(text(await p.call("exec", { command: "echo legacy" })), /legacy/);
    assert.equal(await p.close(), 0);
    noToken(p);
  });

  test("a cancelled call cancels its command", async () => {
    const before = await sandboxIds();
    const p = start();
    await p.call("exec", { command: "true" });
    const ours = (await sandboxIds()).filter((s) => !before.includes(s));
    assert.equal(ours.length, 1);
    const sb = client.sandbox(ours[0]!);
    const id = "slow-1";
    const pending = p.request("tools/call", { name: "exec", arguments: { command: "sleep 60" } }, id, 5000).catch(() => null);
    const deadline = Date.now() + 30000;
    while ((await sb.latestExec())?.state !== "running") {
      assert.ok(Date.now() < deadline, "the command did not start");
      await pause(50);
    }
    p.send({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: id, reason: "test" } });
    while ((await sb.latestExec())?.result?.cancelled !== true) {
      assert.ok(Date.now() < deadline, "the command was not cancelled");
      await pause(50);
    }
    assert.equal(await pending, null, "a cancelled request gets no answer");
    assert.match(text(await p.call("exec", { command: "echo after" })), /after/);
    assert.equal(await p.close(), 0);
    noToken(p);
  });

  test("a sandbox that ended is replaced, and the model is told", async () => {
    const p = start({ HELLOVM_LIFETIME: "1" });
    await p.call("write_file", { path: "/tmp/f", content: "x" });
    await pause(1500);
    let r = await p.call("read_file", { path: "/tmp/f" });
    for (let i = 0; i < 20 && !text(r).startsWith("Note"); i++) {
      await pause(500);
      r = await p.call("read_file", { path: "/tmp/f" });
    }
    assert.match(text(r), /^Note: the previous sandbox ended \(.*lifetime.*\); this call ran in a new, empty sandbox/);
    assert.match(text(r), /Error \(404 not_found\)/);
    assert.equal(await p.close(), 0);
    noToken(p);
  });
});
