/**
 * Tool results shaped for a model: what happened stated plainly first
 * (exit code, timeout, signal), then the output, with a clear note where
 * output was cut. Pure functions, unit tested.
 */

import type { ExecResult } from "hellovm";

/** The API's truncation rule: the first and the last half of `limit` bytes, the omission marked in between. */
export function truncateBytes(data: Uint8Array, limit: number): { bytes: Uint8Array; omitted: number } {
  if (data.byteLength <= limit) return { bytes: data, omitted: 0 };
  const head = Math.floor(limit / 2);
  const tail = limit - head;
  const omitted = data.byteLength - head - tail;
  const marker = new TextEncoder().encode(omission(omitted));
  const out = new Uint8Array(head + marker.byteLength + tail);
  out.set(data.subarray(0, head), 0);
  out.set(marker, head);
  out.set(data.subarray(data.byteLength - tail), head + marker.byteLength);
  return { bytes: out, omitted };
}

/** The line the API puts where it cut the middle of a stream. */
export function omission(bytes: number): string {
  return `\n[... ${bytes} bytes omitted ...]\n`;
}

function stream(name: string, text: string, truncated: boolean, total: number): string {
  if (!text && !truncated) return `--- ${name}: empty ---`;
  const note = truncated
    ? ` (${total} bytes in all, too long: only its start and end are shown, the middle is replaced by a "[... N bytes omitted ...]" line)`
    : "";
  return `--- ${name}${note} ---\n${text}${text.endsWith("\n") ? "" : "\n"}--- end of ${name} ---`;
}

function status(r: ExecResult, timeout: number): string {
  if (r.timedOut) return `Timed out after ${timeout} s: the command was killed (signal ${r.signal ?? 9}).`;
  if (r.cancelled) return `Cancelled: the command was killed (signal ${r.signal ?? 9}).`;
  if (r.signal !== null) return `Killed by signal ${r.signal}.`;
  return `Exit code: ${r.exitCode ?? "unknown"}`;
}

/** The result of a shell command. */
export function formatExec(r: ExecResult, timeout: number): string {
  return [
    status(r, timeout),
    stream("stdout", r.stdout, r.stdoutTruncated, r.stdoutBytes),
    stream("stderr", r.stderr, r.stderrTruncated, r.stderrBytes),
  ].join("\n");
}

/** The result of a stateful Python call. */
export function formatPython(r: ExecResult, timeout: number): string {
  const lines: string[] = [];
  if (r.timedOut) {
    lines.push(`Timed out after ${timeout} s and was interrupted.`);
  } else if (r.cancelled) {
    lines.push("Cancelled.");
  }
  if (r.error) {
    lines.push(`Raised ${r.error.type}: ${r.error.message}`, r.error.traceback.trimEnd());
  } else if (r.value !== null) {
    lines.push(`Value: ${r.value}`);
  } else if (!r.timedOut && !r.cancelled) {
    lines.push("Done (no value).");
  }
  if (r.stdout || r.stdoutTruncated) lines.push(stream("stdout", r.stdout, r.stdoutTruncated, r.stdoutBytes));
  if (r.stderr || r.stderrTruncated) lines.push(stream("stderr", r.stderr, r.stderrTruncated, r.stderrBytes));
  if (r.stateLost) {
    lines.push(
      "Note: the interpreter's state was lost (it was killed or it exited): variables, imports and objects from earlier calls are gone; the next call starts a fresh interpreter.",
    );
  }
  return lines.join("\n");
}

/** A file read for a model: text, cut by the API's rule; binary files are described, not dumped. */
export function formatFile(path: string, data: Uint8Array, limit: number): string {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(data);
  } catch {
    return `${path} is a binary file (${data.byteLength} bytes, not UTF-8 text); it is not shown. Use the exec tool (xxd, base64, file) to look at it.`;
  }
  if (data.byteLength === 0) return `${path} is empty.`;
  const { bytes, omitted } = truncateBytes(data, limit);
  if (!omitted) return text;
  const cut = new TextDecoder().decode(bytes);
  return `${cut}\n[${path} is ${data.byteLength} bytes, too long: only its start and end are shown, the middle is replaced by a "[... ${omitted} bytes omitted ...]" line. Use the exec tool (sed -n, head, tail, grep) to read the rest.]`;
}

/** Removes a secret from text that leaves the server (defence in depth: the token is never put there). */
export function redact(text: string, secret: string): string {
  return secret ? text.split(secret).join("[redacted]") : text;
}
