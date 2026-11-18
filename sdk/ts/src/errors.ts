/**
 * The errors the SDK throws. Every one is a {@link HellovmError}. An error
 * answer of the API is an {@link APIError} with its HTTP `status`, its
 * `code` (the API's `error.code`, e.g. `busy`) and its `message`; the
 * common ones have subclasses. A request that got no answer is a
 * {@link TransportError}, whose `maybeSent` says whether the server may
 * have received it. An answer that cannot be what the API sends is a
 * {@link ResponseError}.
 */

export class HellovmError extends Error {
  override name = "HellovmError";
}

export class APIError extends HellovmError {
  override name = "APIError";
  constructor(
    readonly status: number,
    readonly code: string,
    readonly apiMessage: string,
  ) {
    super(`${status} ${code}: ${apiMessage}`);
  }
}

/** 401: no token, or one the API does not know. */
export class AuthenticationError extends APIError {
  override name = "AuthenticationError";
}

/** 404: no such sandbox (or another tenant's), file, template or exec. */
export class NotFoundError extends APIError {
  override name = "NotFoundError";
}

/** 409: the sandbox is running another request or exec. */
export class BusyError extends APIError {
  override name = "BusyError";
}

/** 410: the sandbox was removed; the message says why. */
export class SandboxEndedError extends APIError {
  override name = "SandboxEndedError";
  get reason(): string {
    const prefix = "the sandbox ended: ";
    return this.apiMessage.startsWith(prefix) ? this.apiMessage.slice(prefix.length) : this.apiMessage;
  }
}

/** 413 `too_large`, 429 `tenant_limit` / `too_many_polls`, 507 `no_space`. */
export class LimitError extends APIError {
  override name = "LimitError";
}

/** 422: an edit's `old` text does not occur (`no_match`) or is `ambiguous`. */
export class EditError extends APIError {
  override name = "EditError";
}

/** No answer: the connection failed, or the request timed out or was aborted. */
export class TransportError extends HellovmError {
  override name = "TransportError";
  /** `false` only when the request certainly did not reach the server. */
  readonly maybeSent: boolean;
  constructor(message: string, options: { maybeSent: boolean; cause?: unknown }) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.maybeSent = options.maybeSent;
  }
}

/** The whole exchange did not finish within the request's timeout. */
export class RequestTimeoutError extends TransportError {
  override name = "RequestTimeoutError";
}

/** The request was stopped by the caller's `AbortSignal` (or `close()`). */
export class AbortedError extends TransportError {
  override name = "AbortedError";
}

/** An answer that is malformed, of the wrong shape, or too large. */
export class ResponseError extends HellovmError {
  override name = "ResponseError";
}

const BY_STATUS: Record<number, new (status: number, code: string, message: string) => APIError> = {
  401: AuthenticationError,
  404: NotFoundError,
  409: BusyError,
  410: SandboxEndedError,
  413: LimitError,
  422: EditError,
  429: LimitError,
  507: LimitError,
};

/** The error for an error answer (any body: a proxy's page is kept short). */
export function apiError(status: number, body: Uint8Array): APIError {
  let code = "";
  let message = "";
  const text = new TextDecoder().decode(body);
  try {
    const value: unknown = JSON.parse(text);
    const error = typeof value === "object" && value !== null ? (value as { error?: unknown }).error : undefined;
    if (typeof error === "object" && error !== null) {
      const e = error as { code?: unknown; message?: unknown };
      if (typeof e.code === "string") code = e.code;
      if (typeof e.message === "string") message = e.message;
    }
  } catch {
    // not JSON
  }
  if (!code) {
    code = "http_error";
    message = text.slice(0, 512);
  }
  const Kind = BY_STATUS[status] ?? APIError;
  return new Kind(status, code.slice(0, 128), message.slice(0, 4096));
}
