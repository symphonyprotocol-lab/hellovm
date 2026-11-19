/**
 * TypeScript SDK for hellovm sandboxes (Node.js 20+, no dependencies).
 *
 * ```ts
 * import { Client } from "hellovm";
 * const client = new Client({ baseUrl: "http://127.0.0.1:7070", token });
 * await client.withSandbox({}, async (sandbox) => {
 *   console.log((await sandbox.exec("echo hi")).stdout);
 * });
 * ```
 */

export { Client, Execution, Sandbox, MAX_FILE } from "./client.js";
export type { BusyPolicy, ClientOptions, CreateOptions, ExecOptions, RunOptions, StreamOptions, StreamPythonOptions } from "./client.js";
export type {
  ExecResult,
  ExecStatus,
  ExposedPort,
  Ingress,
  OmittedEvent,
  OutputEvent,
  PythonError,
  Quotas,
  ResultEvent,
  SandboxInfo,
  StreamEvent,
  Template,
  TenantUsage,
  Usage,
} from "./model.js";
export {
  APIError,
  AbortedError,
  AuthenticationError,
  BudgetExceededError,
  BusyError,
  EditError,
  HellovmError,
  LimitError,
  NotFoundError,
  RateLimitError,
  RequestTimeoutError,
  ResponseError,
  SandboxEndedError,
  TransportError,
} from "./errors.js";
