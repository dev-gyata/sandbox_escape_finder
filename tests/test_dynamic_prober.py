"""Dynamic prober tests: report shape, payload normalization, and the timeout
fallback path."""

from __future__ import annotations

import pytest

from sandbox_escape_finder import (
    DynamicProber,
    canary_oracle,
    sandbox_exec,
)
from sandbox_escape_finder.dynamic_prober import (
    _is_valid_outcome,
    _sandbox_spec,
    _status_for,
)

REQUIRED_KEYS = {
    "id",
    "technique",
    "effect",
    "static_flagged",
    "static_techniques",
    "executed",
    "raised",
    "exception",
    "escaped",
    "duration_s",
    "outcome",
}


def _prober():
    return DynamicProber(sandbox_exec, canary_oracle, {"subprocess_timeout_s": 8})


def test_report_row_shape():
    report = _prober().run(["x = 1\n"])
    assert len(report) == 1
    assert REQUIRED_KEYS <= set(report[0])


def test_payload_accepts_str_dict_and_payload_types():
    corpus = [
        "y = 2\n",
        {"id": "d1", "technique": "import_access", "effect": "canary_write", "code": "import os\n"},
    ]
    report = _prober().run(corpus)
    ids = {r["id"] for r in report}
    assert "custom_0" in ids
    assert "d1" in ids


def test_timeout_is_recorded_as_fallback():
    """An infinite-loop payload must hit the subprocess timeout and be recorded
    as a Timeout (not hang the suite, not count as an escape)."""
    prober = DynamicProber(sandbox_exec, canary_oracle, {"subprocess_timeout_s": 1})
    report = prober.run(["while True:\n    pass\n"])
    row = report[0]
    assert row["escaped"] is False
    assert row["exception"] == "Timeout"


def test_invalid_payload_type_rejected():
    with pytest.raises(TypeError):
        _prober().run([123])


def test_sandbox_spec_rejects_lambda():
    with pytest.raises(ValueError):
        _sandbox_spec(lambda code: None)


def test_sandbox_spec_accepts_module_level_function():
    assert _sandbox_spec(sandbox_exec) == "sandbox_escape_finder.sandbox:sandbox_exec"


def test_raw_fd_stdout_leak_does_not_crash_corpus():
    """H1 regression: a payload that writes raw bytes to fd 1 must not corrupt
    the JSON channel or abort the rest of the corpus run."""
    from sandbox_escape_finder import toy_unrestricted_exec

    corpus = [
        "import os\nos.write(1, b'RAWLEAK not json')\n",  # pollutes fd 1
        "ok = 1\n",  # must still run and be reported
    ]
    prober = DynamicProber(toy_unrestricted_exec, canary_oracle, {"subprocess_timeout_s": 8})
    report = prober.run(corpus)
    assert len(report) == 2
    # Neither row is a RunnerError caused by a parse crash.
    assert all(r["exception"] != "RunnerError" for r in report)


def test_executed_is_false_on_compile_rejection():
    """A RestrictedPython SyntaxError (compile-time rejection) means the body
    never executed."""
    report = _prober().run(["b = __builtins__\n"])
    row = report[0]
    assert row["exception"] == "SyntaxError"
    assert row["executed"] is False
    assert row["escaped"] is False


def test_seed_makes_execution_order_reproducible():
    corpus = [f"v = {i}\n" for i in range(6)]
    r1 = DynamicProber(sandbox_exec, canary_oracle, {"seed": 42}).run(corpus)
    r2 = DynamicProber(sandbox_exec, canary_oracle, {"seed": 42}).run(corpus)
    order1 = [row["exec_order"] for row in r1]
    order2 = [row["exec_order"] for row in r2]
    assert order1 == order2
    # Report is returned in corpus order regardless of exec order.
    assert [row["id"] for row in r1] == [f"custom_{i}" for i in range(6)]


def test_extra_payloads_from_config_are_appended():
    config = {
        "extra_payloads": [
            {"technique": "import_access", "effect": "canary_write", "code": "import sys\n"}
        ]
    }
    prober = DynamicProber(sandbox_exec, canary_oracle, config)
    report = prober.run(["z = 3\n"])
    assert len(report) == 2


def test_extra_payload_metadata_preserved():
    config = {
        "extra_payloads": [
            {"id": "my_extra", "technique": "import_access", "effect": "canary_write", "code": "import sys\n"}
        ]
    }
    report = DynamicProber(sandbox_exec, canary_oracle, config).run([])
    assert report[0]["id"] == "my_extra"
    assert report[0]["effect"] == "canary_write"


def test_is_valid_outcome_rejects_wrong_shapes():
    assert not _is_valid_outcome([])
    assert not _is_valid_outcome({})
    assert not _is_valid_outcome(None)
    assert not _is_valid_outcome({"ran": True})  # missing fields
    good = {
        "ran": True, "raised": False, "exception_type": None,
        "exception_msg": None, "result_repr": "1", "stdout": "",
    }
    assert _is_valid_outcome(good)


def test_wrong_shape_child_json_becomes_runner_error(monkeypatch):
    """A child that emits valid JSON of the wrong shape (e.g. `[]`) must degrade
    to a RunnerError row, not crash run()."""
    import subprocess as sp

    class _FakeProc:
        returncode = 0
        stdout = stderr = stdin = None

        def communicate(self, input=None, timeout=None):
            return ("[]", "")  # valid JSON, wrong shape

    monkeypatch.setattr(sp, "Popen", lambda *a, **k: _FakeProc())
    report = DynamicProber(sandbox_exec, canary_oracle).run(["x = 1\n"])
    assert report[0]["exception"] == "RunnerError"
    assert report[0]["status"] == "errored"
    assert report[0]["escaped"] is False


def test_status_classification_and_errored_analysis():
    from sandbox_escape_finder import false_positive_negative_analysis

    assert _status_for(True, None) == "escaped"
    assert _status_for(False, "Timeout") == "errored"
    assert _status_for(False, "RunnerError") == "errored"
    assert _status_for(False, "SyntaxError") == "blocked"
    rows = [
        {"id": "a", "static_flagged": True, "escaped": False, "status": "errored"},
        {"id": "b", "static_flagged": True, "escaped": False, "status": "blocked"},
    ]
    analysis = false_positive_negative_analysis(rows)
    assert analysis["errored"] == ["a"]
    assert analysis["flagged_no_escape"] == ["b"]  # errored row excluded
