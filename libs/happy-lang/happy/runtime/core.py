"""Public API of the Happy runtime execution layer.

Importing this module gives access to the whole runtime surface:

* :class:`RuntimeContext` — the object a generated program runs inside;
* :class:`ContractChecker` / :class:`ContractPolicy` — dynamic contracts;
* :class:`CapabilityChecker` / :class:`CapabilityRegistry` — capability rules;
* :class:`Secret` / :class:`SecretGuard` / :func:`reveal` — secret protection;
* :class:`Task` / :class:`Channel` / :class:`Scheduler` — async primitives;
* the :class:`HappyRuntimeError` hierarchy for failures.

Typical use::

    from happy.runtime import RuntimeContext

    ctx = RuntimeContext(filename="demo.hpy", source=src, module=ir_module)
    ctx.prepare(module_globals)
    result = ctx.run(module_globals["main"])
    print(result.output)
"""

from __future__ import annotations

from .async_runtime import (
    Channel,
    Scheduler,
    Task,
    await_all,
    gather,
    run,
    select,
    sleep,
    spawn,
)
from .capability import (
    CapabilityChecker,
    CapabilityPolicy,
    CapabilityRegistry,
    OperationRecord,
    normalise_action,
    requires_capability,
)
from .context import RunResult, RuntimeContext
from .contracts import (
    ContractChecker,
    ContractPolicy,
    ContractRecord,
    ContractViolationInfo,
)
from .errors import (
    AsyncRuntimeError,
    CapabilityDenied,
    ContractViolation,
    DivisionByZeroError,
    HappyIndexError,
    HappyKeyError,
    HappyNameError,
    HappyPanic,
    HappyRuntimeError,
    HappyTypeError,
    InvariantViolation,
    PermissionDenied,
    PostconditionViolation,
    PreconditionViolation,
    RuleViolation,
    SecretLeakError,
    format_runtime_error,
    translate_python_error,
)
from .secrets import REDACTED, Secret, SecretGuard, is_secret, reveal, secret
from .values import (
    UNIT,
    Err,
    HappyEnumValue,
    HappyStruct,
    NONE,
    Ok,
    Option,
    Result,
    Some,
    VariantCtor,
    deep_redact,
    to_display,
)

__all__ = [
    # context
    "RuntimeContext",
    "RunResult",
    # contracts
    "ContractChecker",
    "ContractPolicy",
    "ContractRecord",
    "ContractViolationInfo",
    # capabilities
    "CapabilityChecker",
    "CapabilityPolicy",
    "CapabilityRegistry",
    "OperationRecord",
    "normalise_action",
    "requires_capability",
    # secrets
    "Secret",
    "SecretGuard",
    "REDACTED",
    "secret",
    "reveal",
    "is_secret",
    # async
    "Task",
    "Channel",
    "Scheduler",
    "spawn",
    "gather",
    "await_all",
    "sleep",
    "select",
    "run",
    # values
    "UNIT",
    "HappyStruct",
    "HappyEnumValue",
    "VariantCtor",
    "Option",
    "Result",
    "Ok",
    "Err",
    "Some",
    "NONE",
    "to_display",
    "deep_redact",
    # errors
    "HappyRuntimeError",
    "ContractViolation",
    "PreconditionViolation",
    "PostconditionViolation",
    "InvariantViolation",
    "RuleViolation",
    "CapabilityDenied",
    "PermissionDenied",
    "SecretLeakError",
    "HappyTypeError",
    "HappyNameError",
    "HappyIndexError",
    "HappyKeyError",
    "DivisionByZeroError",
    "AsyncRuntimeError",
    "HappyPanic",
    "translate_python_error",
    "format_runtime_error",
]
