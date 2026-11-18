"""When a request is tried again, and how long to wait before it.

A request is tried again only when doing so cannot do something twice:

* the connection could not be made (nothing was sent): any request;
* no answer after sending (the server may have acted): only idempotent
  requests, i.e. reads (``GET``), ``DELETE`` and cancelling an exec;
  never create, exec, starting an exec, write, edit or reset;
* ``409 busy`` (the sandbox refused before doing anything): any request
  that can get it, until the busy deadline, unless the client raises at
  once (``busy="raise"``);
* ``503`` (``template_not_ready``, ``node_full``, or the server's
  connection limit: nothing happened): any request, until the busy
  deadline;
* ``429 too_many_polls``: polls only;
* ``429 rate_limited`` (refused before anything was done): any request,
  after the answer's ``Retry-After``, until the busy deadline.

``429 budget_exceeded`` is not retried: the budget comes back at the end
of the period, usually far later than any deadline.
"""

from __future__ import annotations

import random

from .errors import TransportError

#: First and longest wait between two tries, seconds.
BASE_DELAY = 0.05
MAX_DELAY = 1.0


def delay(attempt: int, rng: random.Random | None = None) -> float:
    """The wait before try ``attempt + 1`` (``attempt`` counts from 0):
    doubling from ``BASE_DELAY`` up to ``MAX_DELAY``, with jitter (half to
    all of it), so that clients waiting on one sandbox do not retry in
    step."""
    full = min(MAX_DELAY, BASE_DELAY * (1 << min(attempt, 16)))
    r: float = (rng or random).random()
    return full * (0.5 + 0.5 * r)


def transport_retry(error: TransportError, idempotent: bool) -> bool:
    """Whether a request that failed with ``error`` may be sent again."""
    return idempotent or not error.maybe_sent


def status_retry(status: int, code: str, *, busy_wait: bool, poll: bool) -> bool:
    """Whether an error answer may be retried (subject to the deadline)."""
    if status == 409 and code == "busy":
        return busy_wait
    if status == 503:
        return True
    if status == 429 and code == "too_many_polls":
        return poll
    if status == 429 and code == "rate_limited":
        return True
    return False
