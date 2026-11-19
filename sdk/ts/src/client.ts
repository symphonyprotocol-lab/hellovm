import { AbortedError, HellovmError, LimitError, ResponseError, TransportError, apiError, retryAfter } from "./errors.js";
import { type Fetch, type HttpResponse, send, sleep } from "./http.js";
import {
  type ExecResult,
  type ExecStatus,
  type ExposedPort,
  type Ingress,
  type Poll,
  type SandboxInfo,
  type StreamEvent,
  type Template,
  type TenantUsage,
  parseIngress,
  parseJson,
  parsePoll,
  parseResult,
  parseSandbox,
  parseStatus,
  parseTemplate,
  parseUsage,
} from "./model.js";
import * as retry from "./retry.js";

/** The API's largest file; a larger write is refused before sending. */
export const MAX_FILE = 16 << 20;
/** The API's default exec timeout, seconds. */
export const DEFAULT_EXEC_TIMEOUT = 60;
/** How much longer than the exec's timeout a request waits for its answer. */
export const EXEC_MARGIN = 30;
/**
 * Longest a single request waits for an exec's answer, seconds. Node's
 * `fetch` gives up on a response whose head has not come after 300 s, so
 * an exec that may run longer is started and followed by polls instead.
 */
export const MAX_BLOCKING = 240;
/** Longest a poll waits on the server (the API allows 30 s). */
export const POLL_WAIT = 25;
const POLL_MARGIN = 15;

const SEGMENT = /^[A-Za-z0-9._~-]{1,128}$/;

function segment(value: string, what: string): string {
  if (typeof value !== "string" || !SEGMENT.test(value)) throw new TypeError(`malformed ${what}: ${JSON.stringify(value)}`);
  return value;
}

export type BusyPolicy = "wait" | "raise";

export interface ClientOptions {
  /** The API's base URL, e.g. `http://127.0.0.1:7070`. */
  baseUrl: string;
  /** The tenant's bearer token. */
  token: string;
  /** Seconds for each request that does not run an exec (default 60). */
  timeout?: number;
  /** What a request does when its sandbox is busy (409): wait and retry (default) or throw. */
  busy?: BusyPolicy;
  /** Seconds to keep retrying a busy sandbox (default 120). */
  busyTimeout?: number;
  /** Tries after a failed connection (default 2; see `retry.ts` for which requests). */
  retries?: number;
  /** Largest answer accepted (default 32 MiB). */
  maxResponseBytes?: number;
  /** A `fetch` to use instead of the global one. */
  fetch?: Fetch;
}

export interface CreateOptions {
  template?: string;
  /** Seconds without a request before the sandbox is removed. */
  idleTimeout?: number;
  /** Seconds after which it is removed. */
  lifetime?: number;
}

export interface RunOptions {
  /** Seconds (default 60, at most 3600); the command is killed after it. */
  timeout?: number;
  stdin?: string;
  /** Bytes kept per output stream (default 64 KiB). */
  maxOutput?: number;
  /** Aborting cancels the exec in the sandbox and rejects with an `AbortedError`. */
  signal?: AbortSignal;
}

export interface ExecOptions extends RunOptions {
  cwd?: string;
  env?: Record<string, string>;
}

export interface StreamOptions extends ExecOptions {
  /** Bytes a poll returns at most (1 KiB to 1 MiB; default the API's 256 KiB). */
  pollBytes?: number;
}

export interface StreamPythonOptions extends StreamOptions {
  stateful?: boolean;
}

interface RequestOptions {
  body?: Uint8Array | string;
  json?: unknown;
  expect?: number[];
  timeout?: number;
  idempotent: boolean;
  poll?: boolean;
  signal?: AbortSignal | undefined;
  /**
   * `false`: the signal stops the waits between tries, but not a request
   * in flight (whose answer is needed to know what to cancel).
   */
  abortInFlight?: boolean;
  goneAfterRetryOk?: boolean;
}

/** A client of one hellovm API with one tenant's token. */
export class Client {
  readonly baseUrl: string;
  readonly timeout: number;
  readonly busy: BusyPolicy;
  readonly busyTimeout: number;
  readonly retries: number;
  readonly maxResponseBytes: number;
  readonly #auth: string;
  readonly #fetch: Fetch;
  readonly #prefix: string;

  constructor(options: ClientOptions) {
    const { token } = options;
    if (typeof token !== "string" || !/^[\x21-\x7e]+$/.test(token)) {
      throw new TypeError("the token must be printable ASCII without spaces");
    }
    let url: URL;
    try {
      url = new URL(options.baseUrl);
    } catch {
      throw new TypeError("the base URL is not a URL");
    }
    if ((url.protocol !== "http:" && url.protocol !== "https:") || !url.hostname) {
      throw new TypeError("the base URL must start with http:// or https:// and name a host");
    }
    if (url.search || url.hash || url.username || url.password) {
      throw new TypeError("the base URL must not have a query, fragment or user");
    }
    this.baseUrl = options.baseUrl;
    this.#prefix = `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
    this.#auth = `Bearer ${token}`;
    this.timeout = options.timeout ?? 60;
    this.busy = options.busy ?? "wait";
    this.busyTimeout = options.busyTimeout ?? 120;
    this.retries = options.retries ?? 2;
    this.maxResponseBytes = options.maxResponseBytes ?? 32 << 20;
    this.#fetch = options.fetch ?? globalThis.fetch;
    if (this.busy !== "wait" && this.busy !== "raise") throw new TypeError('busy must be "wait" or "raise"');
    if (!(this.timeout > 0 && this.busyTimeout >= 0 && this.retries >= 0 && this.maxResponseBytes >= 1024)) {
      throw new TypeError("timeouts, retries and maxResponseBytes must be positive");
    }
  }

  /** A client from `HELLOVM_URL` and `HELLOVM_TOKEN`. */
  static fromEnv(options: Partial<ClientOptions> = {}): Client {
    const baseUrl = process.env.HELLOVM_URL;
    const token = process.env.HELLOVM_TOKEN;
    if (!baseUrl || !token) throw new TypeError("set HELLOVM_URL and HELLOVM_TOKEN");
    return new Client({ ...options, baseUrl, token });
  }

  toJSON(): { baseUrl: string } {
    return { baseUrl: this.baseUrl };
  }

  /** @internal */
  async request(method: string, target: string, o: RequestOptions): Promise<HttpResponse> {
    const headers: Record<string, string> = {
      authorization: this.#auth,
      accept: "application/json",
      "user-agent": "hellovm-ts/0.0.1",
    };
    let body = o.body;
    if (o.json !== undefined) {
      body = JSON.stringify(o.json);
      headers["content-type"] = "application/json";
    } else if (method === "PUT") {
      headers["content-type"] = "application/octet-stream";
    }
    const expect = o.expect ?? [200];
    const started = Date.now();
    let failures = 0;
    let waits = 0;
    const inFlight = o.abortInFlight === false ? undefined : o.signal;
    for (;;) {
      let response: HttpResponse;
      try {
        if (o.signal?.aborted) throw new AbortedError("aborted", { maybeSent: false, cause: o.signal.reason });
        response = await send(this.#fetch, {
          method,
          url: `${this.#prefix}${target}`,
          headers,
          body,
          timeout: o.timeout ?? this.timeout,
          maxBytes: this.maxResponseBytes,
          signal: inFlight,
        });
      } catch (error) {
        if (error instanceof AbortedError || !(error instanceof TransportError)) throw error;
        if (failures >= this.retries || !retry.transportRetry(error, o.idempotent)) throw error;
        await sleep(retry.delay(failures) * 1000, o.signal);
        failures++;
        continue;
      }
      if (expect.includes(response.status)) return response;
      if (o.goneAfterRetryOk && failures > 0 && response.status === 404) return response;
      const error = apiError(response.status, response.body, retryAfter(response.headers.get("retry-after")));
      if (retry.statusRetry(error.status, error.code, { busyWait: this.busy === "wait", poll: o.poll ?? false })) {
        const pause = Math.max(retry.delay(waits), error.retryAfter ?? 0);
        if (Date.now() + pause * 1000 - started <= this.busyTimeout * 1000) {
          waits++;
          await sleep(pause * 1000, o.signal);
          continue;
        }
      }
      throw error;
    }
  }

  async templates(): Promise<Template[]> {
    const d = parseJson((await this.request("GET", "/v1/templates", { idempotent: true })).body) as { templates?: unknown };
    if (!Array.isArray(d?.templates)) throw new ResponseError("templates: expected a list");
    return d.templates.map(parseTemplate);
  }

  /** Makes a sandbox. Not retried after an ambiguous failure (it could make two). */
  async create(options: CreateOptions = {}): Promise<Sandbox> {
    const request: Record<string, unknown> = { template: options.template ?? "python" };
    if (options.idleTimeout !== undefined) request.idle_timeout = options.idleTimeout;
    if (options.lifetime !== undefined) request.lifetime = options.lifetime;
    const r = await this.request("POST", "/v1/sandboxes", { json: request, expect: [201], idempotent: false });
    const info = parseSandbox(parseJson(r.body));
    return new Sandbox(this, segment(info.id, "sandbox id"), info);
  }

  /** Creates a sandbox, passes it to `fn`, and deletes it however `fn` ends. */
  async withSandbox<T>(options: CreateOptions, fn: (sandbox: Sandbox) => Promise<T>): Promise<T> {
    const sandbox = await this.create(options);
    let failed = false;
    try {
      return await fn(sandbox);
    } catch (error) {
      failed = true;
      throw error;
    } finally {
      await sandbox.dispose(failed);
    }
  }

  async list(): Promise<SandboxInfo[]> {
    const d = parseJson((await this.request("GET", "/v1/sandboxes", { idempotent: true })).body) as { sandboxes?: unknown };
    if (!Array.isArray(d?.sandboxes)) throw new ResponseError("sandboxes: expected a list");
    return d.sandboxes.map(parseSandbox);
  }

  /** This tenant's usage in the current metering period, its quotas, and the budgets it used up. */
  async usage(): Promise<TenantUsage> {
    return parseUsage(parseJson((await this.request("GET", "/v1/usage", { idempotent: true })).body));
  }

  /** The sandbox, with its description fetched now. */
  async get(id: string): Promise<Sandbox> {
    const sandbox = this.sandbox(id);
    await sandbox.refresh();
    return sandbox;
  }

  /** A handle on a sandbox by id, without a request. */
  sandbox(id: string): Sandbox {
    return new Sandbox(this, segment(id, "sandbox id"), null);
  }

  /**
   * Deletes a sandbox (a retry that finds it gone after a lost answer is
   * success). When its node does not answer, the API accepts the delete
   * (`202`) and does it on the node later; it is gone for this tenant at once.
   */
  async delete(id: string): Promise<void> {
    await this.request("DELETE", `/v1/sandboxes/${segment(id, "sandbox id")}`, {
      expect: [204, 202, 200],
      idempotent: true,
      goneAfterRetryOk: true,
    });
  }
}

function execRequest(
  what: { command?: string; python?: string; stateful?: boolean },
  o: ExecOptions,
): Record<string, unknown> {
  const r: Record<string, unknown> = { ...what };
  if (!what.stateful) delete r.stateful;
  if (o.timeout !== undefined) r.timeout = o.timeout;
  if (o.cwd !== undefined) r.cwd = o.cwd;
  if (o.env !== undefined) r.env = o.env;
  if (o.stdin !== undefined) r.stdin = o.stdin;
  if (o.maxOutput !== undefined) r.max_output = o.maxOutput;
  return r;
}

function checkPort(port: number): void {
  if (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new TypeError("a port is 1 to 65535");
  }
}

function checkPath(path: string): string {
  if (typeof path !== "string" || !path || path.includes("\0") || new TextEncoder().encode(path).length > 4096) {
    throw new TypeError("a path must be 1 to 4096 bytes without NUL bytes");
  }
  return encodeURIComponent(path);
}

/** One sandbox. `await using` (or `client.withSandbox`) deletes it at the end. */
export class Sandbox implements AsyncDisposable {
  /** The description as last fetched (`null` for a bare handle). */
  info: SandboxInfo | null;

  constructor(
    readonly client: Client,
    readonly id: string,
    info: SandboxInfo | null,
  ) {
    this.info = info;
  }

  /** @internal */
  path(rest = ""): string {
    return `/v1/sandboxes/${this.id}${rest}`;
  }

  async refresh(): Promise<SandboxInfo> {
    this.info = parseSandbox(parseJson((await this.client.request("GET", this.path(), { idempotent: true })).body));
    return this.info;
  }

  delete(): Promise<void> {
    return this.client.delete(this.id);
  }

  /** @internal Deletes it; gone already is fine; other errors only matter if nothing failed before. */
  async dispose(failed: boolean): Promise<void> {
    try {
      await this.delete();
    } catch (error) {
      if (error instanceof HellovmError && "status" in error && (error.status === 404 || error.status === 410)) return;
      if (!failed) throw error;
    }
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.dispose(false);
  }

  async #exec(request: Record<string, unknown>, signal?: AbortSignal): Promise<ExecResult> {
    const timeout = Number(request.timeout ?? DEFAULT_EXEC_TIMEOUT) + EXEC_MARGIN;
    if (signal || !(timeout <= MAX_BLOCKING)) {
      // Start it, then follow it: an abort can cancel it by id, and no
      // single request waits longer than a poll.
      const execution = await this.#start(request, undefined, signal);
      return execution.wait();
    }
    const r = await this.client.request("POST", this.path("/exec"), { json: request, timeout, idempotent: false });
    return parseResult(parseJson(r.body));
  }

  /** Runs `command` with `/bin/sh -c`; never sent twice. */
  exec(command: string, options: ExecOptions = {}): Promise<ExecResult> {
    return this.#exec(execRequest({ command }, options), options.signal);
  }

  /** Runs Python in a fresh fork of the warm interpreter. */
  python(code: string, options: ExecOptions = {}): Promise<ExecResult> {
    return this.#exec(execRequest({ python: code }, options), options.signal);
  }

  /** Runs Python in the stateful interpreter (variables persist between calls). */
  run(code: string, options: RunOptions = {}): Promise<ExecResult> {
    return this.#exec(execRequest({ python: code, stateful: true }, options), options.signal);
  }

  /** Starts `command`; iterate the result for its output, then its result. */
  stream(command: string, options: StreamOptions = {}): Promise<Execution> {
    return this.#start(execRequest({ command }, options), options.pollBytes, options.signal);
  }

  /** Starts Python (a fresh fork, or `stateful`) as an {@link Execution}. */
  streamPython(code: string, options: StreamPythonOptions = {}): Promise<Execution> {
    return this.#start(execRequest({ python: code, stateful: options.stateful ?? false }, options), options.pollBytes, options.signal);
  }

  async #start(request: Record<string, unknown>, pollBytes: number | undefined, signal: AbortSignal | undefined): Promise<Execution> {
    if (pollBytes !== undefined && !(pollBytes >= 1024 && pollBytes <= 1 << 20)) {
      throw new TypeError("pollBytes must be 1024 to 1048576");
    }
    // An abort while this request is in flight does not cut it off: the
    // exec may have started, and only its answer names what to cancel.
    // The execution made from the answer cancels it at once.
    const r = await this.client.request("POST", this.path("/execs"), {
      json: request,
      expect: [201],
      idempotent: false,
      signal,
      abortInFlight: false,
    });
    const status = parseStatus(parseJson(r.body));
    return new Execution(this, segment(status.execId, "exec id"), { pollBytes, signal });
  }

  /** The sandbox's latest exec (the only one it keeps), if any. */
  async latestExec(): Promise<ExecStatus | null> {
    const d = parseJson((await this.client.request("GET", this.path("/execs"), { idempotent: true })).body) as { execs?: unknown };
    if (!Array.isArray(d?.execs)) throw new ResponseError("execs: expected a list");
    return d.execs.length ? parseStatus(d.execs[0]) : null;
  }

  /** Discards the stateful interpreter; whether there was one. */
  async resetPython(): Promise<boolean> {
    const d = parseJson((await this.client.request("POST", this.path("/python/reset"), { idempotent: false })).body) as { had_state?: unknown };
    if (typeof d?.had_state !== "boolean") throw new ResponseError("reset: expected had_state");
    return d.had_state;
  }

  /** The sandbox's ingress token and exposed ports (with their URLs). */
  async ingress(): Promise<Ingress> {
    return parseIngress(parseJson((await this.client.request("GET", this.path("/ingress"), { idempotent: true })).body));
  }

  /**
   * Makes `port` reachable from outside (a server in the sandbox must
   * listen on it, on `0.0.0.0`); it needs the ingress token unless
   * `public`. Calling it again changes `public`. Returns the port with its URL.
   */
  async expose(port: number, options: { public?: boolean } = {}): Promise<ExposedPort> {
    checkPort(port);
    const r = await this.client.request("PUT", this.path(`/ingress/ports/${port}`), {
      json: { public: options.public ?? false },
      idempotent: true,
    });
    const found = parseIngress(parseJson(r.body)).ports.find((p) => p.port === port);
    if (!found) throw new ResponseError("expose: the port is not in the answer");
    return found;
  }

  /** Makes `port` unreachable from outside again (connections already made go on). */
  async unexpose(port: number): Promise<void> {
    checkPort(port);
    await this.client.request("DELETE", this.path(`/ingress/ports/${port}`), { idempotent: true });
  }

  /** Replaces the ingress token with a new one, at once; returns it. */
  async rotateIngressToken(): Promise<string> {
    const r = await this.client.request("POST", this.path("/ingress/token"), { idempotent: false });
    return parseIngress(parseJson(r.body)).token;
  }

  /** The file's bytes (at most 16 MiB). */
  async readFile(path: string): Promise<Uint8Array> {
    return (await this.client.request("GET", this.path(`/files?path=${checkPath(path)}`), { idempotent: true })).body;
  }

  async readText(path: string): Promise<string> {
    return new TextDecoder().decode(await this.readFile(path));
  }

  /** Writes the whole file (creating parent directories); never sent twice. */
  async writeFile(path: string, data: Uint8Array | string): Promise<number> {
    const raw = typeof data === "string" ? new TextEncoder().encode(data) : data;
    if (raw.byteLength > MAX_FILE) throw new LimitError(413, "too_large", `a file is at most ${MAX_FILE} bytes`);
    const r = await this.client.request("PUT", this.path(`/files?path=${checkPath(path)}`), { body: raw, idempotent: false });
    const d = parseJson(r.body) as { bytes?: unknown };
    if (typeof d?.bytes !== "number" || !Number.isInteger(d.bytes)) throw new ResponseError("write: expected bytes");
    return d.bytes;
  }

  /** Replaces the one occurrence of `old` (every one with `replaceAll`); how many. Never sent twice. */
  async editFile(path: string, old: string, replacement: string, options: { replaceAll?: boolean } = {}): Promise<number> {
    checkPath(path);
    const r = await this.client.request("POST", this.path("/files/edit"), {
      json: { path, old, new: replacement, replace_all: options.replaceAll ?? false },
      idempotent: false,
    });
    const d = parseJson(r.body) as { replacements?: unknown };
    if (typeof d?.replacements !== "number" || !Number.isInteger(d.replacements)) throw new ResponseError("edit: expected replacements");
    return d.replacements;
  }
}

/**
 * A streamed exec: an `AsyncIterable` of its output as it comes, ending
 * with a `{type: "result"}` event. It follows the exec by long polls with
 * a byte cursor, so a dropped connection loses nothing (the next poll
 * resumes at {@link Execution.cursor}), and a loop that stops early can
 * be followed by another, which goes on with the next event. `cancel()` cancels the exec in the
 * sandbox (the iteration then ends with the cancelled result); the
 * `signal` given when it started does the same and makes the iteration
 * throw an `AbortedError`; `close()` stops following without cancelling.
 * `await using` cancels it if it has not ended.
 */
export class Execution implements AsyncIterable<StreamEvent>, AsyncDisposable {
  cursor = 0;
  result: ExecResult | null = null;
  readonly pollWait: number;
  readonly resumeTimeout: number;
  readonly #pollBytes: number | undefined;
  readonly #stop = new AbortController();
  readonly #signal: AbortSignal | undefined;
  /** Events of the last poll not yet given to the loop (it may stop between two of them). */
  readonly #pending: StreamEvent[] = [];
  #onAbort: (() => void) | null = null;
  #iterating = false;

  constructor(
    readonly sandbox: Sandbox,
    readonly id: string,
    options: { pollBytes?: number | undefined; signal?: AbortSignal | undefined; pollWait?: number; resumeTimeout?: number } = {},
  ) {
    this.#pollBytes = options.pollBytes;
    this.#signal = options.signal;
    this.pollWait = options.pollWait ?? POLL_WAIT;
    this.resumeTimeout = options.resumeTimeout ?? 60;
    if (this.#signal) {
      const onAbort = () => {
        // Cancel in the sandbox (best effort), and stop following here.
        this.cancel().catch(() => {});
        this.#stop.abort(this.#signal?.reason);
      };
      if (this.#signal.aborted) onAbort();
      else {
        this.#onAbort = onAbort;
        this.#signal.addEventListener("abort", onAbort, { once: true });
      }
    }
  }

  /** The exec ended: an abort has nothing left to cancel. */
  #release(): void {
    if (this.#onAbort) this.#signal?.removeEventListener("abort", this.#onAbort);
    this.#onAbort = null;
  }

  get done(): boolean {
    return this.result !== null;
  }

  async *[Symbol.asyncIterator](): AsyncIterator<StreamEvent> {
    if (this.#iterating) throw new Error("an execution is iterated by one loop at a time");
    this.#iterating = true;
    try {
      for (;;) {
        for (let event = this.#pending.shift(); event !== undefined; event = this.#pending.shift()) yield event;
        if (this.result !== null) return;
        let poll: Poll;
        try {
          poll = await this.#poll();
        } catch (error) {
          if (error instanceof AbortedError && !this.#signal?.aborted) return; // close()
          throw error;
        }
        this.#pending.push(...poll.events);
        if (poll.eof && poll.result) {
          this.result = poll.result;
          this.#release();
          this.#pending.push({ type: "result", result: poll.result });
        }
      }
    } finally {
      this.#iterating = false;
    }
  }

  async #poll(): Promise<Poll> {
    let query = `cursor=${this.cursor}&wait=${this.pollWait}`;
    if (this.#pollBytes !== undefined) query += `&max_bytes=${this.#pollBytes}`;
    const target = this.sandbox.path(`/execs/${this.id}?${query}`);
    let failingSince: number | null = null;
    let attempt = 0;
    let poll: Poll;
    for (;;) {
      try {
        const r = await this.sandbox.client.request("GET", target, {
          timeout: this.pollWait + POLL_MARGIN,
          idempotent: true,
          poll: true,
          signal: this.#stop.signal,
        });
        poll = parsePoll(parseJson(r.body));
        break;
      } catch (error) {
        if (error instanceof AbortedError || !(error instanceof TransportError)) throw error;
        // A dropped connection or a stalled poll: resume from the same cursor.
        const now = Date.now();
        failingSince ??= now;
        if (now - failingSince > this.resumeTimeout * 1000) throw error;
        await sleep(retry.delay(attempt++) * 1000, this.#stop.signal);
      }
    }
    if (poll.execId !== this.id) throw new ResponseError("a poll answered for another exec");
    if (poll.nextCursor < this.cursor) throw new ResponseError("a poll moved the cursor backwards");
    if (!poll.eof && poll.events.length === 0 && poll.nextCursor !== this.cursor) {
      throw new ResponseError("a poll moved the cursor without output");
    }
    this.cursor = poll.nextCursor;
    return poll;
  }

  /** Reads the rest of the output (discarding it) and returns the result. */
  async wait(): Promise<ExecResult> {
    for await (const _ of this) {
      // discard
    }
    if (this.result !== null) return this.result;
    if (this.#signal?.aborted) throw new AbortedError("aborted", { maybeSent: true, cause: this.#signal.reason });
    throw new HellovmError("the execution was closed before it ended");
  }

  /**
   * Cancels the exec (its process group is killed; a stateful call is
   * interrupted first). Resolves once it ended, or after 5 s: the result
   * if it ended. A loop iterating over it ends with the result as usual.
   */
  async cancel(): Promise<ExecResult | null> {
    const r = await this.sandbox.client.request("POST", this.sandbox.path(`/execs/${this.id}/cancel`), { timeout: 30, idempotent: true });
    return parseStatus(parseJson(r.body)).result;
  }

  /** Stops following the exec here (a poll in flight is cut off) without cancelling it. */
  close(): void {
    this.#stop.abort();
  }

  async [Symbol.asyncDispose](): Promise<void> {
    try {
      if (this.result === null) await this.cancel();
    } finally {
      this.#release();
      this.close();
    }
  }
}
