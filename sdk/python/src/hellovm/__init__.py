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
    OmittedEvent,
    OutputEvent,
    PythonError,
    ResultEvent,
    SandboxInfo,
    StreamEvent,
    Template,
)
from .errors import (
    APIError,
    AuthenticationError,
    BusyError,
    EditError,
    HellovmError,
    LimitError,
    NotFoundError,
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
    "BusyError",
    "Client",
    "EditError",
    "ExecResult",
    "ExecStatus",
    "Execution",
    "HellovmError",
    "LimitError",
    "NotFoundError",
    "OmittedEvent",
    "OutputEvent",
    "PythonError",
    "RequestTimeoutError",
    "ResponseError",
    "ResultEvent",
    "Sandbox",
    "SandboxEndedError",
    "SandboxInfo",
    "StreamEvent",
    "Template",
    "TransportError",
]
