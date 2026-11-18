/** The server's configuration, from environment variables. */

export interface Config {
  url: string;
  token: string;
  template: string;
  /** Seconds without a request before the API removes the sandbox (unset: the API's default). */
  idleTimeout: number | undefined;
  /** Seconds the sandbox may live at most (unset: the API's default). */
  lifetime: number | undefined;
  /** An existing sandbox to use instead of creating one (never deleted by the server). */
  sandbox: string | undefined;
  /** Default and largest timeout of a tool call, seconds. */
  defaultTimeout: number;
  maxTimeout: number;
  /** Bytes of each output stream (and of a file read) shown to the model. */
  maxOutput: number;
}

function number(env: NodeJS.ProcessEnv, name: string, fallback: number | undefined, min: number, max: number): number | undefined {
  const raw = env[name];
  if (raw === undefined || raw === "") return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < min || value > max) {
    throw new Error(`${name} must be a number from ${min} to ${max}`);
  }
  return value;
}

export function fromEnv(env: NodeJS.ProcessEnv = process.env): Config {
  const url = env.HELLOVM_URL;
  const token = env.HELLOVM_TOKEN;
  if (!url) throw new Error("set HELLOVM_URL to the hellovm API's base URL (e.g. http://127.0.0.1:7070)");
  if (!token) throw new Error("set HELLOVM_TOKEN to a tenant's token");
  const maxTimeout = number(env, "HELLOVM_MCP_MAX_TIMEOUT", 600, 1, 3600)!;
  return {
    url,
    token,
    template: env.HELLOVM_TEMPLATE || "python",
    idleTimeout: number(env, "HELLOVM_IDLE_TIMEOUT", undefined, 1, 7 * 86400),
    lifetime: number(env, "HELLOVM_LIFETIME", undefined, 1, 7 * 86400),
    sandbox: env.HELLOVM_SANDBOX || undefined,
    defaultTimeout: Math.min(number(env, "HELLOVM_MCP_TIMEOUT", 60, 1, 3600)!, maxTimeout),
    maxTimeout,
    maxOutput: number(env, "HELLOVM_MCP_MAX_OUTPUT", 16384, 256, 1 << 20)!,
  };
}
