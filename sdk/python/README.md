# hellovm (Python SDK)

A client for the hellovm API: sandboxes for AI models, with shell
commands, Python (fresh or in a persistent interpreter), files and
streamed output. Python 3.10 or later, standard library only, typed
(`py.typed`, checked with `mypy --strict`).

```python
from hellovm import Client

client = Client("http://127.0.0.1:7070", token)   # or Client.from_env(): HELLOVM_URL, HELLOVM_TOKEN
with client.create() as sandbox:                 # deleted when the block ends, also on an exception
    r = sandbox.exec("ls / | head -3", timeout=10)
    print(r.exit_code, r.stdout, r.stderr)

    sandbox.run("import math\nx = 2")            # the stateful interpreter
    print(sandbox.run("math.sqrt(x)").value)     # '1.4142135623730951'

    sandbox.write_file("data/in.txt", "hello\n")
    sandbox.edit_file("data/in.txt", "hello", "bye")
    print(sandbox.read_text("data/in.txt"))

    for event in sandbox.stream("make test", timeout=600):   # output as it comes
        if event.type in ("stdout", "stderr"):
            print(event.data, end="")
        elif event.type == "result":
            print("exit", event.result.exit_code)
```

## Surface

| | |
|---|---|
| `Client(base_url, token, *, timeout=60, busy="wait", busy_timeout=120, retries=2, max_response_bytes=32 MiB)` | one tenant's client; thread-safe; `close()` or `with` closes its kept-alive connections |
| `client.templates()`, `client.list()`, `client.get(id)`, `client.sandbox(id)`, `client.delete(id)` | `sandbox(id)` makes a handle without a request; `delete` also succeeds when the API accepts it for later (`202`, the sandbox's node does not answer) |
| `client.usage() -> TenantUsage` | the current metering period (`period_start`, `period_end`, Unix ms), `usage` (`run_ms`, `cpu_ms`, `memory_byte_seconds`, `egress_sent_bytes`, `egress_received_bytes`), `sandboxes`, `memory_limit_bytes`, `quotas`, `exceeded` (`cpu`, `egress`) |
| `client.create(template="python", *, idle_timeout=None, lifetime=None) -> Sandbox` | a context manager that deletes the sandbox on exit |
| `sandbox.exec(command, *, timeout, cwd, env, stdin, max_output) -> ExecResult` | `/bin/sh -c`; returns when it ended |
| `sandbox.python(code, ...)` | Python in a fresh fork of the warm interpreter |
| `sandbox.run(code, *, timeout, stdin, max_output)` | the stateful interpreter: `value`, `error` (type, message, traceback), `state_lost` |
| `sandbox.stream(command, ...)`, `sandbox.stream_python(code, *, stateful=False, ...) -> Execution` | iterate: `OutputEvent`, `OmittedEvent`, then one `ResultEvent`; `cancel()` (any thread), `close()`, `wait()`, `cursor`, `result`; as a context manager it cancels what has not ended |
| `sandbox.read_file(path) -> bytes`, `read_text`, `write_file(path, bytes or str) -> int`, `edit_file(path, old, new, *, replace_all=False) -> int` | at most 16 MiB |
| `sandbox.reset_python() -> bool`, `sandbox.latest_exec()`, `sandbox.refresh()`, `sandbox.delete()` | |
| `sandbox.ingress() -> Ingress` (`token`, `ports`), `expose(port, *, public=False) -> ExposedPort` (`port`, `public`, `url`), `unexpose(port)`, `rotate_ingress_token() -> str` | a server in the sandbox listening on `0.0.0.0:port`, reached from outside at `url`; with the token in `X-Hellovm-Ingress-Token` unless public |

`ExecResult`: `exec_id`, `exit_code`, `signal`, `timed_out`, `cancelled`,
`stdout`, `stderr`, `stdout_truncated`, `stderr_truncated`,
`stdout_bytes`, `stderr_bytes`, `duration_ms`, `value`, `error`,
`state_lost`, and `ok` (exit 0, nothing raised, not timed out or
cancelled). `SandboxInfo.usage` is what the sandbox used so far (the same
counters as `usage`, `None` from an older API). A stream longer than `max_output` keeps its first and last
half with `[... N bytes omitted ...]` between them.

## Errors

Every error is a `HellovmError`. An error answer is an `APIError` with
`status`, `code` and `message` (the API's own); subclasses:
`AuthenticationError` (401), `NotFoundError` (404), `BusyError` (409),
`SandboxEndedError` (410, `reason`), `EditError` (422), `LimitError`
(413, 429, 507) with `RateLimitError` (429 `rate_limited`) and
`BudgetExceededError` (429 `budget_exceeded`: no sandbox or exec until
the period ends; everything else works). `retry_after` is the answer's
`Retry-After` in seconds, when it had one. No answer is a `TransportError` (`RequestTimeoutError`
for a timeout), whose `maybe_sent` says whether the request may have
reached the server. An answer that is not what the API sends, or larger
than `max_response_bytes`, is a `ResponseError`.

## Timeouts, bounds and retries

Every request has one deadline for the whole exchange (connect, send,
head and body), not per socket operation, so a server that trickles
bytes cannot hold a request: `timeout` for most requests, an exec's own
timeout plus 30 s for an exec, 40 s for a poll (which waits 25 s on the
server). Answers are refused past `max_response_bytes` before they are
read; heads are at most 16 KiB and 64 headers.

* **Busy** (`409`): the sandbox runs one request at a time. By default a
  request waits and tries again (backoff from 50 ms to 1 s with jitter)
  until `busy_timeout`; `busy="raise"` raises `BusyError` at once.
* **Idempotent requests** (`GET`: list, get, read a file, poll; `DELETE`;
  cancelling an exec) are tried again after a connection failure or a
  timeout (`retries`, default 2). A retried `DELETE` that finds the
  sandbox gone is success.
* **Not idempotent** (create, exec, starting a stream, write, edit,
  reset): tried again only when the connection could not be made at all.
  After a failure without an answer they raise `TransportError` with
  `maybe_sent=True`: the command may or may not have run, and the SDK
  never runs it a second time.
* **`503`** (template not ready, node full) is retried until
  `busy_timeout`; **`429 too_many_polls`** only for polls;
  **`429 rate_limited`** for any request, after its `Retry-After` (and at
  least the backoff), until `busy_timeout`, then `RateLimitError`.
  `429 budget_exceeded` is raised at once.
* **Streams** follow an exec by long polls with a byte cursor: a dropped
  connection or a stalled poll is resumed from the same cursor for up to
  60 s of failures, and nothing is lost. The SDK never relies on an
  exec id older than the sandbox's latest exec (a sandbox keeps only
  that one).

## Tests

`tests/test_unit.py` runs without a sandbox (parsing, the retry rules,
and the client against a local fake server that stalls, trickles, drops
connections or sends too much). `tests/test_e2e.py` needs a running
plane (`HELLOVM_TEST_URL`, `HELLOVM_TEST_TOKEN`, ...);
`kernel/dev/run-sdk-e2e.sh` at the repository root starts one and runs
both:

```sh
cd sdk/python/tests && PYTHONPATH=../src python3 -m unittest -v
mypy --strict src tests
```
