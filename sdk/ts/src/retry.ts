/**
 * When a request is tried again (the same rules as the Python SDK):
 *
 * - the connection could not be made (nothing was sent): any request;
 * - no answer after sending: only idempotent requests (reads, `DELETE`,
 *   cancelling an exec), never create, exec, starting an exec, write,
 *   edit or reset;
 * - `409 busy`: until the busy deadline, unless `busy: "raise"`;
 * - `503` (`template_not_ready`, `node_full`, a connection limit):
 *   until the busy deadline;
 * - `429 too_many_polls`: polls only.
 */

import type { TransportError } from "./errors.js";

/** First and longest wait between two tries, seconds. */
export const BASE_DELAY = 0.05;
export const MAX_DELAY = 1.0;

/** Seconds to wait before try `attempt + 1`: doubling, capped, with jitter (half to all). */
export function delay(attempt: number, random: () => number = Math.random): number {
  const full = Math.min(MAX_DELAY, BASE_DELAY * 2 ** Math.min(attempt, 16));
  return full * (0.5 + 0.5 * random());
}

export function transportRetry(error: TransportError, idempotent: boolean): boolean {
  return idempotent || !error.maybeSent;
}

export function statusRetry(status: number, code: string, options: { busyWait: boolean; poll: boolean }): boolean {
  if (status === 409 && code === "busy") return options.busyWait;
  if (status === 503) return true;
  if (status === 429 && code === "too_many_polls") return options.poll;
  return false;
}
