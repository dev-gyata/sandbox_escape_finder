"""Dynamic prober: run a payload corpus against a live sandbox and record which
payloads actually escape, comparing that to the static analyzer's verdict.

Design:

* Each payload runs in a **fresh, isolated child process** (see
  :mod:`_subprocess_runner`). The child imports the *same* sandbox callable the
  prober was constructed with (by its ``module:qualname`` spec) and runs the
  payload through it. A per-payload wall-clock timeout kills a runaway child.
* The "escape target" is a **canary file in a throwaway temp directory**, unique
  per payload. The prober snapshots the canary before and after, then asks the
  :data:`oracle` whether an out-of-sandbox effect occurred. No real system path
  is ever used.
* For every payload the prober also records the static analyzer's verdict, so
  the report distinguishes *statically flagged* from *actually escaping* — the
  false-positive / false-negative comparison the task requires.
"""

from __future__ import annotations

import json
import logging
import os
import random
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Iterable, Optional

from .config import Config, load_config
from .oracle import snapshot_canary
from .payloads import Payload
from .static_analyzer import StaticAnalyzer

logger = logging.getLogger(__name__)

Oracle = Callable[[dict, dict, dict], bool]


_MAX_RUNNER_OUTPUT_BYTES = 64 * 1024


class _OutputLimitExceeded(RuntimeError):
    """A child exceeded the bounded stdout/stderr transport budget."""


def _communicate_bounded(
    proc: subprocess.Popen, job: bytes, timeout: float,
) -> tuple[str, str]:
    """Exchange a job over POSIX pipes without unbounded output buffering.

    Multiplex stdin too, so a child that never reads its job still times out.
    Retain at most 64 KiB per output stream; exceeding either budget aborts the
    experiment. The caller owns termination/reaping and final pipe cleanup.
    """
    deadline = time.monotonic() + timeout
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    pending = memoryview(job)
    with selectors.DefaultSelector() as selector:
        for name in ("stdout", "stderr"):
            stream = getattr(proc, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        if pending:
            os.set_blocking(proc.stdin.fileno(), False)
            selector.register(proc.stdin, selectors.EVENT_WRITE, "stdin")
        else:
            proc.stdin.close()

        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(proc.args, timeout)
            for key, _ in selector.select(min(remaining, 1.0)):
                stream, name = key.fileobj, key.data
                if name == "stdin":
                    try:
                        written = os.write(stream.fileno(), pending[:65536])
                        pending = pending[written:]
                    except BrokenPipeError:
                        pending = pending[len(pending):]
                    except BlockingIOError:
                        continue
                    if not pending:
                        selector.unregister(stream)
                        stream.close()
                else:
                    try:
                        chunk = os.read(stream.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        stream.close()
                        continue
                    retained = buffers[name]
                    if len(retained) + len(chunk) > _MAX_RUNNER_OUTPUT_BYTES:
                        raise _OutputLimitExceeded(
                            f"child {name} exceeded output limit of "
                            f"{_MAX_RUNNER_OUTPUT_BYTES} bytes"
                        )
                    retained.extend(chunk)

        # EOF is not proof of process exit: a child can close its own outputs.
        proc.wait(timeout=max(0.0, deadline - time.monotonic()))
    return tuple(buffers[name].decode("utf-8", errors="replace")
                 for name in ("stdout", "stderr"))


def _sandbox_spec(sandbox_exec: Callable[[str], Any]) -> str:
    """Return a ``module:qualname`` spec the child process can import."""
    module = getattr(sandbox_exec, "__module__", None)
    qualname = getattr(sandbox_exec, "__qualname__", None)
    if not module or not qualname or "<locals>" in qualname or "<lambda>" in qualname:
        raise ValueError(
            "isolated execution needs an importable, module-level sandbox callable; "
            f"got {sandbox_exec!r}. Define it at module scope (or run with isolated=False)."
        )
    return f"{module}:{qualname}"


def _normalize_payload(item: Any, index: int) -> dict:
    """Coerce a corpus item (Payload / dict / str) into an internal record."""
    if isinstance(item, Payload):
        return {
            "id": item.id,
            "technique": item.technique,
            "effect": item.effect,
            "template": item.code_template,
        }
    if isinstance(item, dict):
        template = item.get("code_template") or item.get("code")
        if template is None:
            raise ValueError(f"payload[{index}] dict needs a 'code' or 'code_template'")
        return {
            "id": item.get("id", f"custom_{index}"),
            "technique": item.get("technique", "custom"),
            "effect": item.get("effect", "unknown"),
            "template": str(template),
        }
    if isinstance(item, str):
        return {
            "id": f"custom_{index}",
            "technique": "custom",
            "effect": "unknown",
            "template": item,
        }
    raise TypeError(f"payload[{index}] must be a Payload, dict, or str; got {type(item)}")


def _render(template: str, canary_path: str) -> str:
    return template.replace("{canary}", repr(canary_path))


# The exact outcome schema the child runner must emit. Validating the shape (not
# just "is it JSON") means a payload that emits `[]`, `{}`, `null`, or a dict
# missing fields degrades to a RunnerError row instead of crashing run().
_OUTCOME_FIELDS: dict[str, type] = {
    "ran": bool,
    "raised": bool,
    "exception_type": (str, type(None)),  # type: ignore[dict-item]
    "exception_msg": (str, type(None)),  # type: ignore[dict-item]
    "result_repr": (str, type(None)),  # type: ignore[dict-item]
    "stdout": str,
}


def _is_valid_outcome(parsed: Any) -> bool:
    """Return True iff ``parsed`` is a dict matching the outcome schema."""
    if not isinstance(parsed, dict):
        return False
    for field, expected in _OUTCOME_FIELDS.items():
        if field not in parsed:
            return False
        if not isinstance(parsed[field], expected):
            return False
    return True


def _status_for(escaped: bool, exception_type: Optional[str]) -> str:
    """Classify a row as 'escaped', 'errored' (infra failure), or 'blocked'."""
    if escaped:
        return "escaped"
    if exception_type in ("RunnerError", "Timeout"):
        return "errored"
    return "blocked"


class DynamicProber:
    """Runs payloads against a sandbox and reports static-vs-dynamic results.

    Args:
        sandbox_exec: A ``code: str -> result`` callable wrapping the sandbox
            under test. For isolated runs it must be importable at module scope
            (e.g. :func:`sandbox.sandbox_exec`), because a child process imports
            it by name.
        oracle: A ``(pre_state, exec_result, post_state) -> bool`` callable that
            decides whether an escape occurred (see :mod:`oracle`).
        config: Config dict/:class:`Config` (``subprocess_timeout_s``,
            ``enabled_techniques``, ``extra_payloads``, ``seed`` ...).
        isolated: If ``True`` (default) each payload runs in a fresh subprocess.
            ``False`` runs in-process (used only for fast fixture tests).
    """

    def __init__(
        self,
        sandbox_exec: Callable[[str], Any],
        oracle: Oracle,
        config: dict | Config | None = None,
        *,
        isolated: bool = True,
    ) -> None:
        self._sandbox_exec = sandbox_exec
        self._oracle = oracle
        self._config = config if isinstance(config, Config) else load_config(config)
        self._isolated = isolated
        self._analyzer = StaticAnalyzer(self._config)
        self._spec = _sandbox_spec(sandbox_exec) if isolated else None

    # -- execution backends ----------------------------------------------
    def _run_isolated(self, code: str) -> dict:
        job = json.dumps(
            {
                "sandbox_spec": self._spec,
                "code": code,
                # Portable resource backstops applied inside the child: cap CPU
                # seconds (in case a payload is CPU-bound but keeps the pipe
                # quiet) and max file size (so a payload cannot write a giant
                # canary/file to exhaust the host before the wall-clock timeout).
                "limits": {
                    "cpu_s": int(self._config.subprocess_timeout_s) + 2,
                    "fsize_bytes": 16 * 1024 * 1024,
                },
            }
        )
        # start_new_session=True puts the child in its own process group so that,
        # on timeout, we can SIGKILL the whole group — not just the immediate
        # child — reaping any grandchildren an escaping payload may have forked.
        proc = subprocess.Popen(
            [sys.executable, "-I", "-m", "sandbox_escape_finder._subprocess_runner"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            out, err = _communicate_bounded(
                proc, job.encode("utf-8"), self._config.subprocess_timeout_s,
            )
        except (subprocess.TimeoutExpired, _OutputLimitExceeded) as exc:
            self._kill_group(proc)
            # Reap only the direct child, with a bound. Do not communicate()
            # again: an escaped grandchild could keep a pipe open or flood it.
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
            timed_out = isinstance(exc, subprocess.TimeoutExpired)
            return {
                "ran": timed_out,
                "raised": True,
                "exception_type": "Timeout" if timed_out else "RunnerError",
                "exception_msg": (
                    f"exceeded {self._config.subprocess_timeout_s}s"
                    if timed_out else str(exc)
                ),
                "result_repr": None,
                "stdout": "",
            }
        except BaseException:
            self._kill_group(proc)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
            raise
        finally:
            for pipe in (proc.stdin, proc.stdout, proc.stderr):
                if pipe is not None:
                    pipe.close()

        # Robust parse: if the child emitted a valid, well-SHAPED outcome, trust
        # it even on a non-zero exit (a crash during interpreter teardown should
        # not discard a real outcome). Anything else — non-JSON (an adversarial
        # payload prepended raw bytes), or valid JSON of the wrong shape such as
        # `[]`/`{}`/`null` — degrades to a RunnerError row instead of letting a
        # single payload abort the whole corpus run.
        out_stripped = (out or "").strip()
        if out_stripped:
            try:
                parsed = json.loads(out_stripped)
            except (json.JSONDecodeError, UnicodeError):
                logger.warning("child produced undecodable stdout (%d bytes)", len(out_stripped))
                parsed = None
            if _is_valid_outcome(parsed):
                return parsed
            if parsed is not None:
                logger.warning("child produced JSON of unexpected shape: %r", type(parsed).__name__)
        return {
            "ran": False,
            "raised": True,
            "exception_type": "RunnerError",
            "exception_msg": (err or out or "")[:500],
            "result_repr": None,
            "stdout": out_stripped[:2000],
        }

    @staticmethod
    def _kill_group(proc: subprocess.Popen) -> None:
        """SIGKILL the child's whole process group, with fallbacks.

        Because the child was started with ``start_new_session=True`` it is its
        own group leader, so its PGID equals its PID. We signal that saved PID
        directly rather than via ``os.getpgid`` (which can fail if the leader
        has already exited while a grandchild lingers).
        """
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass

    def _run_in_process(self, code: str) -> dict:
        outcome = {
            "ran": False,
            "raised": False,
            "exception_type": None,
            "exception_msg": None,
            "result_repr": None,
            "stdout": "",
        }
        try:
            result = self._sandbox_exec(code)
            outcome["ran"] = True
            outcome["result_repr"] = repr(result)
        except BaseException as exc:  # noqa: BLE001
            outcome["ran"] = True
            outcome["raised"] = True
            outcome["exception_type"] = type(exc).__name__
            outcome["exception_msg"] = str(exc)[:500]
        return outcome

    # -- public API -------------------------------------------------------
    def run(self, payload_corpus: Iterable[Any]) -> list[dict]:
        """Execute every payload and return one report row per payload.

        Each row contains: ``id``, ``technique``, ``effect``,
        ``static_flagged`` (+ ``static_techniques``), ``executed``, ``raised``,
        ``exception``, ``escaped`` (oracle verdict), ``duration_s``, and the raw
        sandbox ``outcome``.
        """
        records = [_normalize_payload(p, i) for i, p in enumerate(payload_corpus)]
        # Append config-provided extra payloads, numbering ids by final position.
        for extra in self._config.extra_payloads:
            records.append(_normalize_payload(extra, len(records)))

        # `seed` drives the execution order: a fixed seed makes the order (and
        # thus any ordering-dependent timing/log) reproducible, while still
        # exercising payloads in a non-trivial order. The returned report is
        # re-sorted back to corpus order so callers (and the README table) see a
        # stable layout regardless of seed.
        order = list(range(len(records)))
        random.Random(self._config.seed).shuffle(order)
        logger.info(
            "running %d payloads (seed=%d, isolated=%s, timeout=%.1fs)",
            len(records),
            self._config.seed,
            self._isolated,
            self._config.subprocess_timeout_s,
        )

        rows: dict[int, dict] = {}
        with tempfile.TemporaryDirectory(prefix="sef_canary_") as tmp:
            for exec_pos, idx in enumerate(order):
                rec = records[idx]
                canary_path = os.path.join(tmp, f"canary_{idx}.txt")
                code = _render(rec["template"], canary_path)

                # Static verdict on the exact code that will run.
                findings = self._analyzer.scan_safe(code)
                static_techniques = sorted({f["technique"] for f in findings})
                static_flagged = bool(static_techniques)

                pre = snapshot_canary(canary_path)
                start = time.perf_counter()
                outcome = (
                    self._run_isolated(code)
                    if self._isolated
                    else self._run_in_process(code)
                )
                duration = time.perf_counter() - start
                post = snapshot_canary(canary_path)

                escaped = bool(self._oracle(pre, outcome, post))
                # "executed" = the sandbox actually ran the payload body. A
                # compile-time SyntaxError (RestrictedPython rejecting the
                # source) means it never executed; a RunnerError means the child
                # never produced an outcome.
                executed = bool(
                    outcome["ran"]
                    and outcome.get("exception_type") not in ("SyntaxError", "RunnerError")
                )

                logger.info(
                    "payload %-28s technique=%-30s executed=%s escaped=%s exc=%s %.3fs",
                    rec["id"],
                    rec["technique"],
                    executed,
                    escaped,
                    outcome.get("exception_type"),
                    duration,
                )

                rows[idx] = {
                    "id": rec["id"],
                    "technique": rec["technique"],
                    "effect": rec["effect"],
                    "static_flagged": static_flagged,
                    "static_techniques": static_techniques,
                    "executed": executed,
                    "raised": outcome["raised"],
                    "exception": outcome["exception_type"],
                    "escaped": escaped,
                    "status": _status_for(escaped, outcome["exception_type"]),
                    "duration_s": round(duration, 4),
                    "exec_order": exec_pos,
                    "outcome": outcome,
                }

        # Return in corpus order for a stable, seed-independent layout.
        return [rows[i] for i in range(len(records))]


def false_positive_negative_analysis(report: list[dict]) -> dict:
    """Summarise static-vs-dynamic disagreements.

    Returns a dict with:

    * ``flagged_no_escape`` — payloads the static analyzer flagged that did NOT
      escape dynamically, **excluding** runs that errored out. These are
      correct detections the sandbox then *blocked* (interpret with ``effect``).
    * ``escaped_not_flagged`` — payloads that escaped but were NOT statically
      flagged (true false negatives of the static analyzer — the dangerous
      case).
    * ``errored`` — payloads whose run was inconclusive (RunnerError / Timeout).
      These are kept separate so a broken execution environment is NOT counted
      as "the sandbox blocked it": a corpus where everything errored must not
      look like a corpus the sandbox successfully resisted.
    * ``counts`` — totals for a quick results table.
    """
    errored = [r["id"] for r in report if r.get("status") == "errored"]
    flagged_no_escape = [
        r["id"]
        for r in report
        if r["static_flagged"] and not r["escaped"] and r.get("status") != "errored"
    ]
    escaped_not_flagged = [
        r["id"] for r in report if r["escaped"] and not r["static_flagged"]
    ]
    return {
        "flagged_no_escape": flagged_no_escape,
        "escaped_not_flagged": escaped_not_flagged,
        "errored": errored,
        "counts": {
            "total": len(report),
            "static_flagged": sum(1 for r in report if r["static_flagged"]),
            "escaped": sum(1 for r in report if r["escaped"]),
            "blocked": sum(1 for r in report if r.get("status") == "blocked"),
            "errored": len(errored),
            "flagged_no_escape": len(flagged_no_escape),
            "escaped_not_flagged": len(escaped_not_flagged),
        },
    }
