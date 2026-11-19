/**
 * The tools and the one sandbox behind them.
 *
 * One implicit sandbox per server process: created on the first tool call
 * that needs it, used by every call after, and deleted when the server
 * exits (an idle timeout reclaims it if the server is killed). A model
 * never handles ids. If the sandbox ended (idle timeout, lifetime,
 * memory), the next call makes a new one and says so at the top of its
 * result; `reset_sandbox` starts over on purpose.
 */

import {
  APIError,
  BudgetExceededError,
  Client,
  HellovmError,
  NotFoundError,
  RateLimitError,
  type Sandbox,
  SandboxEndedError,
} from "hellovm";
import { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";

import type { Config } from "./config.js";
import { formatExec, formatFile, formatPython, redact } from "./format.js";

export const VERSION = "0.0.1";

type ToolResult = { content: { type: "text"; text: string }[]; isError?: boolean };

export class SandboxHolder {
  readonly client: Client;
  #sandbox: Sandbox | null = null;
  #creating: Promise<Sandbox> | null = null;
  #notice: string | null = null;

  constructor(readonly config: Config) {
    this.client = new Client({ baseUrl: config.url, token: config.token });
    if (config.sandbox) this.#sandbox = this.client.sandbox(config.sandbox);
  }

  /** The sandbox, made on first use. */
  async get(): Promise<Sandbox> {
    if (this.#sandbox) return this.#sandbox;
    this.#creating ??= this.client
      .create({
        template: this.config.template,
        ...(this.config.idleTimeout !== undefined ? { idleTimeout: this.config.idleTimeout } : {}),
        ...(this.config.lifetime !== undefined ? { lifetime: this.config.lifetime } : {}),
      })
      .then((sandbox) => {
        this.#sandbox = sandbox;
        log(`created sandbox ${sandbox.id}`);
        return sandbox;
      })
      .finally(() => {
        this.#creating = null;
      });
    return this.#creating;
  }

  /** Forgets a sandbox that ended, so that the next call makes a new one. */
  ended(sandbox: Sandbox, why: string): void {
    if (this.#sandbox !== sandbox || this.config.sandbox) return;
    this.#sandbox = null;
    this.#notice = `Note: the previous sandbox ended (${why}); this call ran in a new, empty sandbox: files, processes and Python state from before are gone.`;
    log(`sandbox ${sandbox.id} ended: ${why}`);
  }

  takeNotice(): string | null {
    const n = this.#notice;
    this.#notice = null;
    return n;
  }

  /**
   * Deletes the sandbox the server made (`deleted`; `none` if there is
   * none yet), or, for a sandbox it was given, which is not its to
   * delete, starts a fresh interpreter (`restarted`). A sandbox that
   * could not be deleted is kept, so that it can be deleted later.
   */
  async reset(): Promise<"deleted" | "restarted" | "none"> {
    if (this.#creating) await this.#creating.catch(() => {});
    const sandbox = this.#sandbox;
    if (!sandbox) {
      this.#notice = null;
      return "none";
    }
    if (this.config.sandbox) {
      await sandbox.resetPython();
      return "restarted";
    }
    await sandbox.dispose(false);
    if (this.#sandbox === sandbox) this.#sandbox = null;
    this.#notice = null;
    log(`deleted sandbox ${sandbox.id}`);
    return "deleted";
  }

  /** At exit. */
  async close(): Promise<void> {
    if (this.#creating) await this.#creating.catch(() => {});
    const sandbox = this.#sandbox;
    this.#sandbox = null;
    if (sandbox && !this.config.sandbox) {
      try {
        await sandbox.dispose(false);
        log(`deleted sandbox ${sandbox.id}`);
      } catch (error) {
        log(`could not delete sandbox ${sandbox.id}: ${redact(String(error), this.config.token)}`);
      }
    }
  }
}

export function log(line: string): void {
  process.stderr.write(`hellovm-mcp: ${line}\n`);
}

/** Runs `fn` on the sandbox; a sandbox that ended is replaced once. */
async function withSandbox(holder: SandboxHolder, fn: (sandbox: Sandbox) => Promise<string>): Promise<ToolResult> {
  const token = holder.config.token;
  const reply = (text: string, isError = false): ToolResult => {
    const notice = holder.takeNotice();
    const full = notice ? `${notice}\n\n${text}` : text;
    return { content: [{ type: "text", text: redact(full, token) }], ...(isError ? { isError: true } : {}) };
  };
  for (let attempt = 0; ; attempt++) {
    let sandbox: Sandbox;
    try {
      sandbox = await holder.get();
    } catch (error) {
      return reply(`Could not create a sandbox: ${describe(error)}`, true);
    }
    try {
      return reply(await fn(sandbox));
    } catch (error) {
      const gone = error instanceof SandboxEndedError || (error instanceof NotFoundError && error.code === "sandbox_not_found");
      if (gone && attempt === 0 && !holder.config.sandbox) {
        holder.ended(sandbox, error instanceof SandboxEndedError ? error.reason : "it no longer exists");
        continue;
      }
      return reply(describe(error), true);
    }
  }
}

/** An error as the model reads it: the API's own message first, then what it means for the next step. */
export function describe(error: unknown): string {
  if (error instanceof BudgetExceededError) {
    const when = error.retryAfter === null ? "" : ` (in ${error.retryAfter} s)`;
    return (
      `Error (${error.status} ${error.code}): ${error.apiMessage}\n` +
      `No command or Python call can be started, and no sandbox made, until the usage period ends${when}. ` +
      "Reading and writing files still works. Do not retry before then."
    );
  }
  if (error instanceof RateLimitError) {
    const when = error.retryAfter === null ? "a moment" : `${error.retryAfter} s`;
    return `Error (${error.status} ${error.code}): ${error.apiMessage}\nToo many requests: wait ${when} before the next call.`;
  }
  if (error instanceof APIError && error.status === 429 && (error.code === "tenant_limit" || error.code === "memory_limit")) {
    return `Error (${error.status} ${error.code}): ${error.apiMessage}\nThis account has as many sandboxes as it may: another one must be deleted first.`;
  }
  if (error instanceof APIError) return `Error (${error.status} ${error.code}): ${error.apiMessage}`;
  if (error instanceof HellovmError) return `Error: ${error.message}`;
  return `Error: ${error instanceof Error ? error.message : String(error)}`;
}

export function buildServer(holder: SandboxHolder): McpServer {
  const { config } = holder;
  const server = new McpServer(
    { name: "hellovm", version: VERSION },
    {
      capabilities: { tools: {} },
      instructions:
        "Tools for one Linux sandbox (a hellovm sandbox with Python), created on first use and private to this session: " +
        "run shell commands, run Python in a persistent interpreter, read, write and edit files, " +
        "and make an HTTP server in the sandbox reachable from outside. " +
        "Files and the Python interpreter's variables persist between calls; shell variables and the working directory do not.",
    },
  );
  const timeout = (what: string) =>
    z
      .number()
      .positive()
      .max(config.maxTimeout)
      .optional()
      .describe(`Seconds before ${what} (default ${config.defaultTimeout}, at most ${config.maxTimeout}).`);

  server.registerTool(
    "exec",
    {
      title: "Run a shell command",
      description:
        "Runs a command with /bin/sh -c in the sandbox and returns its exit code, stdout and stderr. " +
        `Each output stream shows at most ${config.maxOutput} bytes (its start and end when longer). ` +
        "Each command starts a new shell in the home directory unless cwd is given; files persist between calls. " +
        "Background processes survive if they detach their output (nohup cmd >log 2>&1 &).",
      inputSchema: z.object({
        command: z.string().min(1).describe("The shell command."),
        timeout: timeout("the command is killed"),
        cwd: z.string().optional().describe("Working directory (default: the home directory)."),
      }),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    async ({ command, timeout: t, cwd }, ctx) => {
      const seconds = t ?? config.defaultTimeout;
      return withSandbox(holder, async (sandbox) => {
        const r = await sandbox.exec(command, {
          timeout: seconds,
          maxOutput: config.maxOutput,
          signal: ctx.mcpReq.signal,
          ...(cwd !== undefined ? { cwd } : {}),
        });
        return formatExec(r, seconds);
      });
    },
  );

  server.registerTool(
    "python",
    {
      title: "Run Python",
      description:
        "Runs Python code in the sandbox's persistent interpreter, like a notebook cell: variables, imports and objects " +
        "persist between calls. Returns the value of the last expression (if not None), printed output, and the " +
        "exception with its traceback if one was raised. Set restart to start a fresh interpreter first.",
      inputSchema: z.object({
        code: z.string().min(1).describe("Python source to run."),
        timeout: timeout("the code is interrupted (KeyboardInterrupt; killed if it does not stop)"),
        restart: z.boolean().optional().describe("Discard the interpreter's state before running."),
      }),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    async ({ code, timeout: t, restart }, ctx) => {
      const seconds = t ?? config.defaultTimeout;
      return withSandbox(holder, async (sandbox) => {
        if (restart) await sandbox.resetPython();
        const r = await sandbox.run(code, { timeout: seconds, maxOutput: config.maxOutput, signal: ctx.mcpReq.signal });
        return formatPython(r, seconds);
      });
    },
  );

  server.registerTool(
    "read_file",
    {
      title: "Read a file",
      description:
        `Reads a text file from the sandbox (relative paths are relative to the home directory). At most ${config.maxOutput} ` +
        "bytes are shown (its start and end when longer); a binary file is described, not shown.",
      inputSchema: z.object({ path: z.string().min(1).describe("Path of the file.") }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ path }) => withSandbox(holder, async (sandbox) => formatFile(path, await sandbox.readFile(path), config.maxOutput)),
  );

  server.registerTool(
    "write_file",
    {
      title: "Write a file",
      description: "Writes a text file in the sandbox, replacing it whole and creating parent directories.",
      inputSchema: z.object({
        path: z.string().min(1).describe("Path of the file."),
        content: z.string().describe("The file's new contents."),
      }),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    },
    async ({ path, content }) =>
      withSandbox(holder, async (sandbox) => `Wrote ${await sandbox.writeFile(path, content)} bytes to ${path}.`),
  );

  server.registerTool(
    "edit_file",
    {
      title: "Edit a file",
      description:
        "Replaces old_text by new_text in a UTF-8 file in the sandbox. old_text must occur exactly once (include enough " +
        "surrounding lines to make it unique), unless replace_all is set.",
      inputSchema: z.object({
        path: z.string().min(1).describe("Path of the file."),
        old_text: z.string().min(1).describe("The exact text to replace."),
        new_text: z.string().describe("The replacement."),
        replace_all: z.boolean().optional().describe("Replace every occurrence."),
      }),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
    },
    async ({ path, old_text, new_text, replace_all }) =>
      withSandbox(holder, async (sandbox) => {
        const n = await sandbox.editFile(path, old_text, new_text, { replaceAll: replace_all ?? false });
        return `Replaced ${n} occurrence${n === 1 ? "" : "s"} in ${path}.`;
      }),
  );

  const port = z.number().int().min(1).max(65535).describe("The TCP port a server in the sandbox listens on (on 0.0.0.0).");

  server.registerTool(
    "expose_port",
    {
      title: "Make a port reachable from outside",
      description:
        "Makes an HTTP server listening in the sandbox on this port reachable from outside, and returns its URL. " +
        "Unless public is set, requests need the sandbox's ingress token (the result says how to send it). " +
        "The server must listen on 0.0.0.0, not 127.0.0.1. Start the server first (in the background, with nohup).",
      inputSchema: z.object({
        port,
        public: z.boolean().optional().describe("Reachable by anyone, without the token (default false)."),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ port: p, public: open }) =>
      withSandbox(holder, async (sandbox) => {
        const exposed = await sandbox.expose(p, { public: open ?? false });
        if (exposed.public) return `Port ${p} is reachable by anyone at ${exposed.url}`;
        const token = (await sandbox.ingress()).token;
        return (
          `Port ${p} is reachable at ${exposed.url} with the sandbox's ingress token:\n` +
          `send the header X-Hellovm-Ingress-Token: ${token}\n` +
          `or open ${exposed.url}?hellovm_ingress_token=${token} once in a browser (it sets a cookie).`
        );
      }),
  );

  server.registerTool(
    "unexpose_port",
    {
      title: "Stop a port being reachable from outside",
      description: "Makes a port exposed with expose_port unreachable from outside again.",
      inputSchema: z.object({ port }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ port: p }) =>
      withSandbox(holder, async (sandbox) => {
        await sandbox.unexpose(p);
        return `Port ${p} is no longer reachable from outside.`;
      }),
  );

  server.registerTool(
    "reset_sandbox",
    {
      title: config.sandbox ? "Restart the Python interpreter" : "Start over with a new sandbox",
      description: config.sandbox
        ? "Restarts the sandbox's Python interpreter: its variables, imports and objects are lost. " +
          "The sandbox itself is fixed for this server, so its files and processes are kept."
        : "Deletes the sandbox with all its files, processes and Python state; the next call gets a new, empty one.",
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    },
    async () => {
      try {
        const text = {
          deleted: "The sandbox was reset: the next call starts in a new, empty sandbox.",
          restarted:
            "The Python interpreter was restarted: its variables, imports and objects are gone. " +
            "This server uses a fixed sandbox, which is not deleted: its files and processes are still there.",
          none: "There was no sandbox yet; the next call creates one.",
        }[await holder.reset()];
        return { content: [{ type: "text", text }] };
      } catch (error) {
        return { content: [{ type: "text", text: redact(describe(error), config.token) }], isError: true };
      }
    },
  );

  return server;
}
