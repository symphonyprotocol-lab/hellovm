#!/usr/bin/env node
/**
 * hellovm-mcp: an MCP server on stdio that gives a model one hellovm
 * sandbox. Configured by environment variables (see README.md); logs go
 * to stderr and never contain the token.
 */

import { serveStdio } from "@modelcontextprotocol/server/stdio";

import { fromEnv } from "./config.js";
import { SandboxHolder, buildServer, log } from "./tools.js";

let config;
try {
  config = fromEnv();
} catch (error) {
  log(error instanceof Error ? error.message : String(error));
  process.exit(2);
}

const holder = new SandboxHolder(config);
let url = config.url;
try {
  url = new URL(config.url).origin;
} catch {
  // the client refuses it at the first call
}
log(`serving on stdio: API ${url}, template ${config.template}${config.sandbox ? `, sandbox ${config.sandbox}` : ""}`);

const handle = serveStdio(() => buildServer(holder), {
  onerror: (error) => log(`protocol error: ${error.message}`),
});

let closing = false;
async function shutdown(code: number): Promise<void> {
  if (closing) return;
  closing = true;
  const timer = setTimeout(() => process.exit(code), 10_000);
  timer.unref();
  await handle.close().catch(() => {});
  await holder.close();
  process.exit(code);
}

process.stdin.on("end", () => void shutdown(0));
process.stdin.on("close", () => void shutdown(0));
process.on("SIGINT", () => void shutdown(130));
process.on("SIGTERM", () => void shutdown(143));
