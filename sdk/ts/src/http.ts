/**
 * One HTTP exchange with Node's built-in `fetch`, bounded: a deadline for
 * the whole exchange (head and body), a cap on the body read (checked
 * against `Content-Length` before reading, and while reading), and the
 * caller's `AbortSignal`. Redirects are refused (the token must not
 * follow them anywhere).
 */

import { AbortedError, RequestTimeoutError, ResponseError, TransportError } from "./errors.js";

export interface HttpResponse {
  status: number;
  headers: Headers;
  body: Uint8Array;
}

export interface HttpRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: Uint8Array | string | undefined;
  /** Seconds for the whole exchange. */
  timeout: number;
  maxBytes: number;
  signal?: AbortSignal | undefined;
}

export type Fetch = typeof fetch;

/** Error codes of a connection that was never made: nothing was sent. */
const NOT_SENT = new Set(["ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN", "EHOSTUNREACH", "ENETUNREACH", "UND_ERR_CONNECT_TIMEOUT"]);

function errorCode(error: unknown): string | undefined {
  for (let e: unknown = error, depth = 0; e && depth < 4; depth++) {
    const code = (e as { code?: unknown }).code;
    if (typeof code === "string") return code;
    e = (e as { cause?: unknown }).cause;
  }
  return undefined;
}

export async function send(fetchImpl: Fetch, req: HttpRequest): Promise<HttpResponse> {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, Math.max(1, Math.ceil(req.timeout * 1000)));
  const onAbort = () => controller.abort();
  if (req.signal?.aborted) {
    clearTimeout(timer);
    throw new AbortedError("aborted", { maybeSent: false, cause: req.signal.reason });
  }
  req.signal?.addEventListener("abort", onAbort, { once: true });
  const failed = (error: unknown, maybeSent: boolean): TransportError => {
    if (timedOut) return new RequestTimeoutError(`no complete answer within ${req.timeout} s`, { maybeSent: true, cause: error });
    if (req.signal?.aborted) return new AbortedError("aborted", { maybeSent, cause: req.signal.reason });
    const cause = (error as { cause?: { message?: unknown } } | undefined)?.cause;
    if (cause?.message === "bad port") {
      return new TransportError(`fetch refuses the API's port (a port the Fetch standard blocks): run the API on another port`, {
        maybeSent: false,
        cause: error,
      });
    }
    const code = errorCode(error);
    const sent = maybeSent && !(code !== undefined && NOT_SENT.has(code));
    return new TransportError(`${sent ? "connection failed" : "cannot connect to the API"}: ${code ?? String(error)}`, {
      maybeSent: sent,
      cause: error,
    });
  };
  try {
    let response: Response;
    try {
      response = await fetchImpl(req.url, {
        method: req.method,
        headers: req.headers,
        body: req.body,
        signal: controller.signal,
        redirect: "manual",
      });
    } catch (error) {
      throw failed(error, true);
    }
    if (response.status >= 300 && response.status < 400 && response.headers.has("location")) {
      await response.body?.cancel().catch(() => {});
      throw new ResponseError(`the API answered with a redirect (${response.status}); redirects are not followed`);
    }
    const length = response.headers.get("content-length");
    if (length !== null && Number(length) > req.maxBytes) {
      await response.body?.cancel().catch(() => {});
      throw new ResponseError(`the response is larger than ${req.maxBytes} bytes (${length})`);
    }
    const chunks: Uint8Array[] = [];
    let total = 0;
    if (response.body) {
      const reader = response.body.getReader();
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.byteLength;
          if (total > req.maxBytes) {
            await reader.cancel().catch(() => {});
            throw new ResponseError(`the response is larger than ${req.maxBytes} bytes`);
          }
          chunks.push(value);
        }
      } catch (error) {
        if (error instanceof ResponseError) throw error;
        throw failed(error, true);
      }
    }
    const body = new Uint8Array(total);
    let at = 0;
    for (const c of chunks) {
      body.set(c, at);
      at += c.byteLength;
    }
    return { status: response.status, headers: response.headers, body };
  } finally {
    clearTimeout(timer);
    req.signal?.removeEventListener("abort", onAbort);
  }
}

export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new AbortedError("aborted", { maybeSent: false, cause: signal.reason }));
      return;
    }
    const onAbort = () => {
      clearTimeout(timer);
      reject(new AbortedError("aborted", { maybeSent: false, cause: signal?.reason }));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}
