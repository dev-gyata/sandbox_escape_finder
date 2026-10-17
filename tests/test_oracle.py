"""Oracle-correctness tests, including the intentionally-broken toy sandbox."""

from __future__ import annotations

import os

import pytest

from sandbox_escape_finder import (
    DynamicProber,
    canary_oracle,
    sandbox_exec,
    snapshot_canary,
    toy_unrestricted_exec,
)
from sandbox_escape_finder.payloads import Payload


def test_canary_oracle_detects_new_file(tmp_path):
    canary = os.path.join(tmp_path, "c.txt")
    pre = snapshot_canary(canary)
    with open(canary, "w") as fh:
        fh.write("touched")
    post = snapshot_canary(canary)
    assert canary_oracle(pre, {}, post) is True


def test_canary_oracle_detects_content_change(tmp_path):
    canary = os.path.join(tmp_path, "c.txt")
    with open(canary, "w") as fh:
        fh.write("original")
    pre = snapshot_canary(canary)
    with open(canary, "w") as fh:
        fh.write("modified")
    post = snapshot_canary(canary)
    assert canary_oracle(pre, {}, post) is True


def test_canary_oracle_false_when_untouched(tmp_path):
    canary = os.path.join(tmp_path, "c.txt")
    pre = snapshot_canary(canary)
    post = snapshot_canary(canary)
    assert canary_oracle(pre, {}, post) is False


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX mkfifo required")
def test_canary_oracle_detects_irregular_object_without_blocking(tmp_path):
    """A payload planting a FIFO at the canary path is an escape, and the
    snapshot must NOT block trying to read the FIFO."""
    canary = os.path.join(tmp_path, "c.txt")
    pre = snapshot_canary(canary)  # absent
    os.mkfifo(canary)
    post = snapshot_canary(canary)  # must return quickly, not open the FIFO
    assert post["irregular"] is True
    assert post["fingerprint"] is None
    assert canary_oracle(pre, {}, post) is True


def test_snapshot_does_not_follow_symlink(tmp_path):
    target = os.path.join(tmp_path, "secret.txt")
    with open(target, "w") as fh:
        fh.write("sensitive")
    canary = os.path.join(tmp_path, "c.txt")
    os.symlink(target, canary)
    snap = snapshot_canary(canary)
    # A symlink where we expected a regular file is itself irregular; we must
    # not follow it and hash the target's contents.
    assert snap["irregular"] is True
    assert snap["fingerprint"] is None


def test_oracle_catches_broken_toy_sandbox():
    """The toy sandbox runs unrestricted exec, so a write payload MUST escape
    and the oracle MUST flag it. This validates the oracle end-to-end."""
    escape_payload = Payload(
        id="toy_write",
        technique="builtins_restoration",
        effect="canary_write",
        description="plain open() under the broken toy sandbox",
        code_template="open({canary}, 'w').write('pwned')\n",
    )
    prober = DynamicProber(toy_unrestricted_exec, canary_oracle, {"subprocess_timeout_s": 10})
    report = prober.run([escape_payload])
    assert report[0]["escaped"] is True
    assert report[0]["executed"] is True


def test_oracle_reports_no_escape_against_real_restrictedpython():
    """The same write payload must be blocked by the real RestrictedPython
    sandbox (no canary written)."""
    escape_payload = Payload(
        id="rp_write",
        technique="builtins_restoration",
        effect="canary_write",
        description="open() attempt under RestrictedPython",
        code_template="open({canary}, 'w').write('pwned')\n",
    )
    prober = DynamicProber(sandbox_exec, canary_oracle, {"subprocess_timeout_s": 10})
    report = prober.run([escape_payload])
    assert report[0]["escaped"] is False
