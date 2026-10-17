"""Isolated child-process entry point for running one payload.

The dynamic prober launches this module in a *fresh* interpreter
(``python -I -m sandbox_escape_finder._subprocess_runner``) for every payload,
so a payload that corrupts global state, exhausts a resource, or genuinely
escapes can only affect a short-lived child — never the test runner.

Protocol: a single JSON job is read from stdin::

    {"sandbox_spec": "module:qualname", "code": "<python source>"}

The named sandbox callable is imported and invoked as ``sandbox(code)``. The
child captures the outcome and writes exactly one JSON object to stdout::

    {"ran": bool, "raised": bool, "exception_type": str|null,
     "exception_msg": str|null, "result_repr": str|null, "stdout": str}

Anything the sandboxed code prints to real stdout is captured into ``stdout``
so it cannot corrupt the JSON channel.
"""

from __future__ import annotations

import contextlib
import importlib
import io
import json
import os
import sys
from typing import Any, Callable


def _apply_limits(limits: dict) -> None:
    """Apply best-effort resource limits in the child (POSIX only).

    Soft-fails on any platform/limit that is unavailable (e.g. Windows has no
    ``resource`` module; some limits are not enforced on macOS). These are
    backstops, not the primary isolation mechanism.
    """
    try:
        import resource
    except ImportError:
        return
    cpu_s = limits.get("cpu_s")
    if isinstance(cpu_s, int) and cpu_s > 0:
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s))
        except (ValueError, OSError):
            pass
    fsize = limits.get("fsize_bytes")
    if isinstance(fsize, int) and fsize > 0:
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
        except (ValueError, OSError):
            pass


def _load_sandbox(spec: str) -> Callable[[str], Any]:
    module_name, _, qualname = spec.partition(":")
    if not module_name or not qualname:
        raise ValueError(f"invalid sandbox spec {spec!r}; expected 'module:qualname'")
    module = importlib.import_module(module_name)
    obj: Any = module
    for part in qualname.split("."):
        obj = getattr(obj, part)
    if not callable(obj):
        raise TypeError(f"sandbox spec {spec!r} is not callable")
    return obj


def main() -> None:
    job = json.load(sys.stdin)
    spec = job["sandbox_spec"]
    code = job["code"]
    _apply_limits(job.get("limits", {}))

    outcome: dict[str, Any] = {
        "ran": False,
        "raised": False,
        "exception_type": None,
        "exception_msg": None,
        "result_repr": None,
        "stdout": "",
    }

    captured = io.StringIO()

    # Keep a private copy of the *real* stdout fd, then point fd 1 at os.devnull
    # for the duration of the payload. This defends the JSON channel even
    # against a payload that writes raw bytes to fd 1 (e.g. os.write(1, ...)),
    # which a Python-level redirect_stdout alone does not catch.
    real_stdout_fd = os.dup(1)
    devnull_fd = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull_fd, 1)
    os.close(devnull_fd)
    try:
        sandbox = _load_sandbox(spec)
        with contextlib.redirect_stdout(captured):
            result = sandbox(code)
        outcome["ran"] = True
        try:
            outcome["result_repr"] = repr(result)[:2000]
        except Exception:  # pragma: no cover - repr of exotic objects
            outcome["result_repr"] = "<unrepresentable>"
    except BaseException as exc:  # noqa: BLE001 - we must report every failure mode
        outcome["ran"] = True
        outcome["raised"] = True
        outcome["exception_type"] = type(exc).__name__
        outcome["exception_msg"] = str(exc)[:500]
    finally:
        outcome["stdout"] = captured.getvalue()[:2000]
        # Restore the real stdout fd before writing the JSON result.
        os.dup2(real_stdout_fd, 1)
        os.close(real_stdout_fd)

    # The JSON result is the only thing on real stdout.
    sys.stdout.write(json.dumps(outcome))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
