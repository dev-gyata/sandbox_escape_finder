"""Automated escape oracle.

An *oracle* is a callable ``(pre_state, exec_result, post_state) -> bool`` that
decides, without human inspection, whether a run achieved an out-of-sandbox
effect. We define the out-of-sandbox effect concretely as: *the restricted code
managed to touch a canary file on the real filesystem*. A correctly restricted
sandbox gives the payload no way to reach ``open``/``os``, so the canary stays
untouched; if the canary appears or changes, real I/O happened and the sandbox
was escaped.

The canary always lives in a throwaway temp directory (see
:class:`dynamic_prober.DynamicProber`), never a real system path, so even a
genuine escape only writes an expendable file.
"""

from __future__ import annotations

import hashlib
import os
import stat
from typing import Optional

# Never read more than this many bytes of the canary. A real escape only needs
# to create/touch the file; bounding the read stops a payload that points the
# canary at (or replaces it with) a huge file from exhausting the parent.
_MAX_CANARY_BYTES = 1 << 20  # 1 MiB


def _canary_fingerprint(canary_path: str) -> Optional[str]:
    """Return a content hash of a *regular* canary file, or ``None``.

    The file is opened without following symlinks (``O_NOFOLLOW``) and only if
    it is a regular file (``fstat`` re-check guards against a TOCTOU swap). At
    most :data:`_MAX_CANARY_BYTES` are hashed. Any OS error (missing file, FIFO
    that would block, permission denied) returns ``None`` rather than raising.
    """
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(canary_path, flags)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        hasher = hashlib.sha256()
        remaining = _MAX_CANARY_BYTES
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            hasher.update(chunk)
            remaining -= len(chunk)
        return hasher.hexdigest()
    except OSError:
        return None
    finally:
        os.close(fd)


def snapshot_canary(canary_path: str) -> dict:
    """Capture the canary's existence, content fingerprint, and regularity.

    Used to build ``pre_state`` (before the run) and ``post_state`` (after). The
    snapshot never follows symlinks or reads an unbounded amount, so a hostile
    canary object cannot hang or exhaust the parent process.
    """
    exists = False
    irregular = False
    try:
        mode = os.lstat(canary_path).st_mode
        exists = True
        # Anything that is not a plain regular file where we expected one (a
        # symlink, FIFO, socket, device, directory) is itself evidence the
        # sandbox created an unexpected filesystem object.
        irregular = not stat.S_ISREG(mode)
    except OSError:
        exists = False

    return {
        "canary_path": canary_path,
        "exists": exists,
        "irregular": irregular,
        "fingerprint": None if irregular else _canary_fingerprint(canary_path),
    }


def canary_oracle(pre_state: dict, exec_result: dict, post_state: dict) -> bool:
    """Default oracle: an escape occurred iff the canary file was touched.

    "Touched" means it did not exist (or had different content) before the run
    and now exists with content, i.e. the restricted code performed real
    filesystem I/O it should not have been able to perform.

    Args:
        pre_state: :func:`snapshot_canary` result taken before execution.
        exec_result: The runner's structured outcome (unused here, but part of
            the oracle contract so other oracles can inspect it).
        post_state: :func:`snapshot_canary` result taken after execution.

    Returns:
        ``True`` if an out-of-sandbox filesystem effect is detected: the canary
        appeared, its content changed, or an unexpected (non-regular) filesystem
        object was created at its path.

    Note:
        The built-in corpus writes a canary and leaves it ("create-and-leave").
        A payload that creates *then deletes* the canary within the run would
        leave ``post_state["exists"] == False`` and read as no-escape; detecting
        that would require in-run filesystem watching, which is out of scope.
    """
    appeared = (not pre_state["exists"]) and post_state["exists"]
    changed = (
        pre_state["exists"]
        and post_state["exists"]
        and pre_state["fingerprint"] != post_state["fingerprint"]
    )
    irregular_created = post_state.get("irregular", False) and not pre_state.get(
        "irregular", False
    )
    return bool(appeared or changed or irregular_created)
