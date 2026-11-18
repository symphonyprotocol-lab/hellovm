"""The exceptions the SDK raises.

Every one is a :class:`HellovmError`. An answer of the API that is an error
is an :class:`APIError` carrying its HTTP ``status``, its ``code`` (the
API's ``error.code``, e.g. ``busy`` or ``sandbox_ended``) and its
``message``; the common ones have subclasses. A request that got no
answer is a :class:`TransportError`, whose ``maybe_sent`` says whether the
server may have received it (and so may have acted on it). An answer that
cannot be what the API sends is a :class:`ResponseError`.
"""

from __future__ import annotations

import json


class HellovmError(Exception):
    """Base class of every error of this SDK."""


class APIError(HellovmError):
    """The API answered with an error."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"{status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message


class AuthenticationError(APIError):
    """401: no token, or one the API does not know."""


class NotFoundError(APIError):
    """404: no such sandbox (or another tenant's: the same answer), file,
    template or exec (a sandbox keeps only its latest exec)."""


class BusyError(APIError):
    """409: the sandbox is running another request or exec. Raised when the
    client was made with ``busy="raise"``, or when it stayed busy past
    ``busy_timeout``."""


class SandboxEndedError(APIError):
    """410: the sandbox was removed; ``message`` says why (idle, lifetime,
    memory, its agent ended)."""

    @property
    def reason(self) -> str:
        prefix = "the sandbox ended: "
        return self.message[len(prefix) :] if self.message.startswith(prefix) else self.message


class LimitError(APIError):
    """413 ``too_large``, 429 ``tenant_limit`` or ``too_many_polls``,
    507 ``no_space``: a limit of the API or of the sandbox."""


class EditError(APIError):
    """422: an edit's ``old`` text does not occur (``no_match``) or occurs
    more than once without ``replace_all`` (``ambiguous``)."""


class TransportError(HellovmError):
    """No answer: the connection failed or the request timed out.
    ``maybe_sent`` is ``False`` only when the request certainly did not
    reach the server (the connection could not be made)."""

    def __init__(self, message: str, *, maybe_sent: bool) -> None:
        super().__init__(message)
        self.maybe_sent = maybe_sent


class RequestTimeoutError(TransportError):
    """The whole exchange did not finish within the request's timeout."""


class ResponseError(HellovmError):
    """An answer that is not what the API sends: malformed, of the wrong
    shape, or larger than ``max_response_bytes``."""


_BY_STATUS: dict[int, type[APIError]] = {
    401: AuthenticationError,
    404: NotFoundError,
    409: BusyError,
    410: SandboxEndedError,
    413: LimitError,
    422: EditError,
    429: LimitError,
    507: LimitError,
}


def api_error(status: int, body: bytes) -> APIError:
    """The exception for an error answer. The body is the API's
    ``{"error": {"code", "message"}}``; anything else (a proxy's page, say)
    is kept as a short message."""
    code, message = "", ""
    try:
        value = json.loads(body)
        error = value.get("error") if isinstance(value, dict) else None
        if isinstance(error, dict):
            if isinstance(error.get("code"), str):
                code = error["code"]
            if isinstance(error.get("message"), str):
                message = error["message"]
    except (ValueError, UnicodeDecodeError, RecursionError):
        pass
    if not code:
        code = "http_error"
        message = body[:512].decode("utf-8", "replace")
    code = code[:128]
    message = message[:4096]
    return _BY_STATUS.get(status, APIError)(status, code, message)
