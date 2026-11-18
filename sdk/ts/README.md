# hellovm (TypeScript SDK)

A client for the hellovm API for Node.js 20 or later: ESM with type
declarations, the built-in `fetch`, no runtime dependencies. The same
surface and behaviour as the Python SDK, in camelCase.

```ts
import { Client } from "hellovm";

const client = new Client({ baseUrl: "http://127.0.0.1:7070", token }); // or Client.fromEnv()
await client.withSandbox({}, async (sandbox) => {   // deleted however the callback ends
  const r = await sandbox.exec("ls / | head -3", { timeout: 10 });
  console.log(r.exitCode, r.stdout, r.stderr);

  await sandbox.run("import math\nx = 2");          // the stateful interpreter
  console.log((await sandbox.run("math.sqrt(x)")).value);

  await sandbox.writeFile("data/in.txt", "hello\n");
  await sandbox.editFile("data/in.txt", "hello", "bye");
  console.log(await sandbox.readText("data/in.txt"));

  const controller = new AbortController();
  for await (const event of await sandbox.stream("make test", { timeout: 600, signal: controller.signal })) {
    if (event.type === "stdout" || event.type === "stderr") process.stdout.write(event.data);
    else if (event.type === "result") console.log("exit", event.result.exitCode);
  }
});
```

`await using sandbox = await client.create()` deletes it at the end of
the block too (`Symbol.asyncDispose`).

## Surface

| | |
|---|---|
| `new Client({baseUrl, token, timeout?, busy?, busyTimeout?, retries?, maxResponseBytes?, fetch?})` | seconds; `busy: "wait"` (default) or `"raise"` |
| `templates()`, `list()`, `get(id)`, `sandbox(id)`, `delete(id)`, `create({template?, idleTimeout?, lifetime?})`, `withSandbox(options, fn)` | `delete` also succeeds when accepted for later (`202`) |
| `usage(): TenantUsage` | the metering period (`periodStart`, `periodEnd`), `usage` (`runMs`, `cpuMs`, `memoryByteSeconds`, `egressSentBytes`, `egressReceivedBytes`), `sandboxes`, `memoryLimitBytes`, `quotas`, `exceeded`; `SandboxInfo.usage` has a sandbox's own counters |
| `sandbox.exec(command, {timeout, cwd, env, stdin, maxOutput, signal})` | `ExecResult` when it ended; with a `signal` an abort cancels the command in the sandbox |
| `sandbox.python(code, options)`, `sandbox.run(code, {timeout, stdin, maxOutput, signal})` | a fresh fork; the stateful interpreter (`value`, `error`, `stateLost`) |
| `sandbox.stream(command, options)`, `sandbox.streamPython(code, {stateful, ...})` | an `Execution`: `AsyncIterable` of `{type: "stdout" \| "stderr", data}`, `{type: "omitted", bytes}`, then `{type: "result", result}`; `cancel()`, `close()`, `wait()`, `cursor`, `result`, `Symbol.asyncDispose` (cancels what has not ended) |
| `readFile(path): Uint8Array`, `readText`, `writeFile(path, data): number`, `editFile(path, old, new, {replaceAll}): number` | at most 16 MiB |
| `resetPython(): boolean`, `latestExec()`, `refresh()`, `delete()` | |

Cancelling: `execution.cancel()` cancels the exec in the sandbox (the
iteration then ends with the cancelled result); aborting the `signal`
does the same and makes the iteration (or `exec()`) reject with an
`AbortedError`; `close()` stops following without cancelling.

## Errors, timeouts, bounds and retries

As in the Python SDK: `HellovmError`; `APIError` (`status`, `code`,
`apiMessage`) with `AuthenticationError`, `NotFoundError`, `BusyError`,
`SandboxEndedError` (`reason`), `EditError`, `LimitError` (with
`RateLimitError` and `BudgetExceededError`; `retryAfter` from
`Retry-After`);
`TransportError` (`maybeSent`) with `RequestTimeoutError` and
`AbortedError`; `ResponseError`. Every request has one deadline for the
whole exchange (head and body), the body is read with a size cap (and
refused by its `Content-Length` before reading), redirects are refused.
Busy sandboxes are waited out (or thrown at once), `429 rate_limited`
after its `Retry-After` until the busy deadline, `429 budget_exceeded`
thrown at once; only idempotent
requests are retried after a failure without an answer, never create,
exec, write, edit or reset; streams resume from their cursor. An exec
whose timeout is too long for one request (Node's `fetch` gives up on
an answer after 300 s) is started and followed by polls, like one with
a `signal`. See the
Python SDK's README for the full rules.

## Building and testing

```sh
npm ci
npm run build      # tsc --strict, into dist/
npm test           # unit tests; the end-to-end suite runs when HELLOVM_TEST_URL is set
```

`kernel/dev/run-sdk-e2e.sh` at the repository root builds it and runs
the suites against a real plane. Development dependencies:
`typescript` and `@types/node`.
