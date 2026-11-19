"""Python SDK for hellovm sandboxes.

    from hellovm import Client

    client = Client("http://127.0.0.1:7070", token)
    with client.create() as sandbox:
        print(sandbox.exec("echo hi").stdout)
"""

from ._client import Client, Execution, Sandbox
from ._http import Abort, AbortedError
from ._model import (
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
)
from .errors import (
    APIError,
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
)

__version__ = "0.0.1"

__all__ = [
    "APIError",
    "Abort",
    "AbortedError",
    "AuthenticationError",
    "BudgetExceededError",
    "BusyError",
    "Client",
    "EditError",
    "ExecResult",
    "ExecStatus",
    "Execution",
    "ExposedPort",
    "HellovmError",
    "Ingress",
    "LimitError",
    "NotFoundError",
    "OmittedEvent",
    "OutputEvent",
    "PythonError",
    "Quotas",
    "RateLimitError",
    "RequestTimeoutError",
    "ResponseError",
    "ResultEvent",
    "Sandbox",
    "SandboxEndedError",
    "SandboxInfo",
    "StreamEvent",
    "Template",
    "TenantUsage",
    "TransportError",
    "Usage",
]
