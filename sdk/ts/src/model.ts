/**
 * What the API answers, as typed objects, parsed defensively: every field
 * the SDK uses is checked, unknown fields are ignored (a newer API still
 * works), anything else is a {@link ResponseError}.
 */

import { ResponseError } from "./errors.js";

export interface Template {
  name: string;
  ready: boolean;
}

/** What a sandbox used since it was made, or a tenant's sandboxes in a period. */
export interface Usage {
  runMs: number;
  cpuMs: number;
  memoryByteSeconds: number;
  egressSentBytes: number;
  egressReceivedBytes: number;
  /** Bytes ingress delivered to the sandbox, and from it (0 from an API without ingress). */
  ingressReceivedBytes: number;
  ingressSentBytes: number;
}

/** A port reachable from outside through ingress, at `url`; one not `public` needs the ingress token. */
export interface ExposedPort {
  port: number;
  public: boolean;
  url: string;
}

/**
 * A sandbox's ingress: its token (sent as the `X-Hellovm-Ingress-Token`
 * header, or once as the `hellovm_ingress_token` query parameter, which
 * sets a cookie) and its exposed ports.
 */
export interface Ingress {
  token: string;
  ports: ExposedPort[];
}

/** A tenant's quotas; `null`: no limit. */
export interface Quotas {
  maxSandboxes: number;
  maxMemoryBytes: number | null;
  requestsPerSecond: number | null;
  requestBurst: number | null;
  cpuSecondsPerPeriod: number | null;
  egressBytesPerPeriod: number | null;
  /** Ingress connections to its sandboxes at once (`null`: no ingress). */
  maxIngressConnections: number | null;
}

/**
 * `GET /v1/usage`: the current metering period (Unix ms), what the tenant's
 * sandboxes used in it, its sandboxes and their memory limits now, its
 * quotas, and the budgets it used up (`cpu`, `egress`).
 */
export interface TenantUsage {
  tenant: string;
  periodStart: number;
  periodEnd: number;
  usage: Usage;
  sandboxes: number;
  memoryLimitBytes: number;
  quotas: Quotas;
  exceeded: string[];
}

export interface SandboxInfo {
  id: string;
  tenant: string;
  template: string;
  node: string;
  egressId: string;
  /** Unix milliseconds. */
  createdAt: number;
  lastUsedAt: number;
  expiresAt: number;
  /** Seconds. */
  idleTimeout: number;
  memoryBytes: number;
  memoryLimitBytes: number;
  readyMs: number;
  /** `null` from an API that does not report it. */
  usage: Usage | null;
}

/** The exception a stateful call raised. */
export interface PythonError {
  type: string;
  message: string;
  traceback: string;
}

/**
 * What an exec did. A stream longer than `maxOutput` keeps its first and
 * last half with `[... N bytes omitted ...]` between them (`*Truncated`
 * is then true and `*Bytes` says how much there was).
 */
export interface ExecResult {
  execId: string;
  exitCode: number | null;
  signal: number | null;
  timedOut: boolean;
  cancelled: boolean;
  stdout: string;
  stderr: string;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  stdoutBytes: number;
  stderrBytes: number;
  durationMs: number;
  /** Stateful calls: the `repr` of the last expression's value, if not None. */
  value: string | null;
  /** Stateful calls: the exception raised. */
  error: PythonError | null;
  /** Stateful calls: whether the interpreter's state was lost; `null` otherwise. */
  stateLost: boolean | null;
  /** Exited 0, raised nothing, neither timed out nor was cancelled. */
  ok: boolean;
}

export type OutputEvent = { type: "stdout" | "stderr"; data: string };
export type OmittedEvent = { type: "omitted"; bytes: number };
export type ResultEvent = { type: "result"; result: ExecResult };
/** What a stream yields: output in the order produced, then the result. */
export type StreamEvent = OutputEvent | OmittedEvent | ResultEvent;

export interface ExecStatus {
  execId: string;
  kind: string;
  state: string;
  startedAt: number;
  cancelRequested: boolean;
  result: ExecResult | null;
}

export interface Poll {
  execId: string;
  state: string;
  events: (OutputEvent | OmittedEvent)[];
  nextCursor: number;
  eof: boolean;
  result: ExecResult | null;
}

type Obj = Record<string, unknown>;

export function parseJson(body: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    throw new ResponseError("the answer is not JSON");
  }
}

function obj(v: unknown, what: string): Obj {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new ResponseError(`${what}: expected an object`);
  return v as Obj;
}

function str(d: Obj, key: string, what: string): string {
  const v = d[key];
  if (typeof v !== "string") throw new ResponseError(`${what}: \`${key}\` is not a string`);
  return v;
}

function bool(d: Obj, key: string, what: string, dflt?: boolean): boolean {
  const v = d[key] ?? dflt;
  if (typeof v !== "boolean") throw new ResponseError(`${what}: \`${key}\` is not a boolean`);
  return v;
}

function num(d: Obj, key: string, what: string): number {
  const v = d[key];
  if (typeof v !== "number" || !Number.isFinite(v)) throw new ResponseError(`${what}: \`${key}\` is not a number`);
  return v;
}

function count(d: Obj, key: string, what: string): number {
  const v = num(d, key, what);
  if (!Number.isInteger(v) || v < 0) throw new ResponseError(`${what}: \`${key}\` is not a count`);
  return v;
}

function optInt(d: Obj, key: string, what: string): number | null {
  const v = d[key];
  if (v === null || v === undefined) return null;
  if (typeof v !== "number" || !Number.isInteger(v)) throw new ResponseError(`${what}: \`${key}\` is not an integer`);
  return v;
}

export function parseTemplate(v: unknown): Template {
  const d = obj(v, "template");
  return { name: str(d, "name", "template"), ready: bool(d, "ready", "template") };
}

export function parseSandbox(v: unknown): SandboxInfo {
  const w = "sandbox";
  const d = obj(v, w);
  return {
    id: str(d, "id", w),
    tenant: str(d, "tenant", w),
    template: str(d, "template", w),
    node: str(d, "node", w),
    egressId: str(d, "egress_id", w),
    createdAt: count(d, "created_at", w),
    lastUsedAt: count(d, "last_used_at", w),
    expiresAt: count(d, "expires_at", w),
    idleTimeout: num(d, "idle_timeout", w),
    memoryBytes: count(d, "memory_bytes", w),
    memoryLimitBytes: count(d, "memory_limit_bytes", w),
    readyMs: num(d, "ready_ms", w),
    usage: d.usage === null || d.usage === undefined ? null : parseCounters(d.usage),
  };
}

export function parseCounters(v: unknown): Usage {
  const w = "usage";
  const d = obj(v, w);
  return {
    runMs: count(d, "run_ms", w),
    cpuMs: count(d, "cpu_ms", w),
    memoryByteSeconds: count(d, "memory_byte_seconds", w),
    egressSentBytes: count(d, "egress_sent_bytes", w),
    egressReceivedBytes: count(d, "egress_received_bytes", w),
    ingressReceivedBytes: optCount(d, "ingress_received_bytes", w) ?? 0,
    ingressSentBytes: optCount(d, "ingress_sent_bytes", w) ?? 0,
  };
}

export function parseIngress(v: unknown): Ingress {
  const w = "ingress";
  const d = obj(v, w);
  if (!Array.isArray(d.ports)) throw new ResponseError("ingress: `ports` is not a list");
  const ports = d.ports.map((p: unknown) => {
    const q = obj(p, "port");
    const port = count(q, "port", "port");
    if (port < 1 || port > 65535) throw new ResponseError("port: out of range");
    return { port, public: bool(q, "public", "port"), url: str(q, "url", "port") };
  });
  return { token: str(d, "token", w), ports };
}

function optCount(d: Obj, key: string, what: string): number | null {
  return d[key] === null || d[key] === undefined ? null : count(d, key, what);
}

function optNum(d: Obj, key: string, what: string): number | null {
  return d[key] === null || d[key] === undefined ? null : num(d, key, what);
}

export function parseUsage(v: unknown): TenantUsage {
  const w = "usage";
  const d = obj(v, w);
  const period = obj(d.period, "period");
  const q = obj(d.quotas, "quotas");
  const exceeded = d.exceeded;
  if (!Array.isArray(exceeded) || !exceeded.every((x) => typeof x === "string")) {
    throw new ResponseError("usage: `exceeded` is not a list of names");
  }
  return {
    tenant: str(d, "tenant", w),
    periodStart: count(period, "start", "period"),
    periodEnd: count(period, "end", "period"),
    usage: parseCounters(d.usage),
    sandboxes: count(d, "sandboxes", w),
    memoryLimitBytes: count(d, "memory_limit_bytes", w),
    quotas: {
      maxSandboxes: count(q, "max_sandboxes", "quotas"),
      maxMemoryBytes: optCount(q, "max_memory_bytes", "quotas"),
      requestsPerSecond: optNum(q, "requests_per_second", "quotas"),
      requestBurst: optCount(q, "request_burst", "quotas"),
      cpuSecondsPerPeriod: optNum(q, "cpu_seconds_per_period", "quotas"),
      egressBytesPerPeriod: optCount(q, "egress_bytes_per_period", "quotas"),
      maxIngressConnections: optCount(q, "max_ingress_connections", "quotas"),
    },
    exceeded: exceeded as string[],
  };
}

export function parseResult(v: unknown): ExecResult {
  const w = "exec result";
  const d = obj(v, w);
  let error: PythonError | null = null;
  if (d.error !== null && d.error !== undefined) {
    const e = obj(d.error, "exec error");
    error = { type: str(e, "type", "exec error"), message: str(e, "message", "exec error"), traceback: str(e, "traceback", "exec error") };
  }
  const value = d.value ?? null;
  if (value !== null && typeof value !== "string") throw new ResponseError(`${w}: \`value\` is not a string`);
  const stateLost = d.state_lost ?? null;
  if (stateLost !== null && typeof stateLost !== "boolean") throw new ResponseError(`${w}: \`state_lost\` is not a boolean`);
  const result = {
    execId: typeof d.exec_id === "string" ? d.exec_id : "",
    exitCode: optInt(d, "exit_code", w),
    signal: optInt(d, "signal", w),
    timedOut: bool(d, "timed_out", w),
    cancelled: bool(d, "cancelled", w, false),
    stdout: str(d, "stdout", w),
    stderr: str(d, "stderr", w),
    stdoutTruncated: bool(d, "stdout_truncated", w),
    stderrTruncated: bool(d, "stderr_truncated", w),
    stdoutBytes: count(d, "stdout_bytes", w),
    stderrBytes: count(d, "stderr_bytes", w),
    durationMs: num(d, "duration_ms", w),
    value,
    error,
    stateLost,
  };
  return { ...result, ok: result.exitCode === 0 && error === null && !result.timedOut && !result.cancelled };
}

export function parseStatus(v: unknown): ExecStatus {
  const w = "exec";
  const d = obj(v, w);
  return {
    execId: str(d, "exec_id", w),
    kind: str(d, "kind", w),
    state: str(d, "state", w),
    startedAt: count(d, "started_at", w),
    cancelRequested: bool(d, "cancel_requested", w),
    result: d.result === null || d.result === undefined ? null : parseResult(d.result),
  };
}

export function parseEvent(v: unknown): OutputEvent | OmittedEvent {
  const d = obj(v, "output event");
  if (d.type === "stdout" || d.type === "stderr") return { type: d.type, data: str(d, "data", "output event") };
  if (d.type === "omitted") return { type: "omitted", bytes: count(d, "bytes", "output event") };
  throw new ResponseError(`unknown output event type ${JSON.stringify(String(d.type).slice(0, 32))}`);
}

export function parsePoll(v: unknown): Poll {
  const w = "poll";
  const d = obj(v, w);
  if (!Array.isArray(d.events)) throw new ResponseError(`${w}: \`events\` is not a list`);
  const eof = bool(d, "eof", w);
  const result = d.result === null || d.result === undefined ? null : parseResult(d.result);
  if (eof && result === null) throw new ResponseError(`${w}: the end without a result`);
  return {
    execId: str(d, "exec_id", w),
    state: str(d, "state", w),
    events: d.events.map(parseEvent),
    nextCursor: count(d, "next_cursor", w),
    eof,
    result,
  };
}
