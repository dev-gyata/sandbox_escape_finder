"""Exercise buffering limits while data arrives, including real child pipes."""

import subprocess
import sys
import tracemalloc

import pytest

from sandbox_escape_finder import DynamicProber, canary_oracle, sandbox_exec, toy_unrestricted_exec
from sandbox_escape_finder import _subprocess_runner as runner
from sandbox_escape_finder import dynamic_prober


def test_child_capture_retains_a_prefix_without_accumulating_discarded_text():
    capture = runner._BoundedTextBuffer(2000)
    chunk = "x" * 16384
    tracemalloc.start()
    try:
        for _ in range(512):
            assert capture.write(chunk) == len(chunk)
        capture.writelines([chunk, chunk])
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert capture.getvalue() == "x" * 2000
    assert peak < 256 * 1024


def test_empty_writes_do_not_accumulate_buffer_entries():
    capture = runner._BoundedTextBuffer(2000)
    tracemalloc.start()
    try:
        for _ in range(65536):
            capture.write("")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert capture.getvalue() == ""
    assert peak < 256 * 1024


def test_real_runner_uses_bounded_capture_during_execution():
    code = (
        "import tracemalloc\n"
        "chunk = 'x' * 16384\n"
        "tracemalloc.start()\n"
        "for i in range(512):\n"
        "    print(chunk, end='')\n"
        "current, peak = tracemalloc.get_traced_memory()\n"
        "tracemalloc.stop()\n"
        "result = peak\n"
    )
    row = DynamicProber(toy_unrestricted_exec, canary_oracle).run([code])[0]
    assert row["exception"] is None
    assert len(row["outcome"]["stdout"]) == 2000
    assert int(row["outcome"]["result_repr"]) < 256 * 1024


def test_restricted_print_collector_is_bounded_too():
    source = "for i in range(512):\n    print('x' * 16384)\nresult = printed\n"
    tracemalloc.start()
    try:
        result = sandbox_exec(source)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result == "x" * 2000
    assert peak < 512 * 1024


@pytest.mark.parametrize("fd", [1, 2])
def test_parent_stops_output_flood_before_accumulating_it(fd):
    code = f"import os; os.read(0, 1); os.write({fd}, b'x' * (8 * 1024 * 1024))"
    proc = subprocess.Popen(
        [sys.executable, "-c", code],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True,
    )
    tracemalloc.start()
    try:
        with pytest.raises(RuntimeError, match="output limit"):
            dynamic_prober._communicate_bounded(proc, b"j", timeout=3)
        _, peak = tracemalloc.get_traced_memory()
        assert peak < 512 * 1024
    finally:
        tracemalloc.stop()
        proc.kill()
        proc.wait(timeout=3)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            stream.close()


def test_output_limit_is_inconclusive_and_does_not_abort_remaining_candidates():
    report = DynamicProber(
        toy_unrestricted_exec, canary_oracle, {"subprocess_timeout_s": 3},
    ).run([
        "import os\nos.write(2, b'x' * (256 * 1024))",
        "result = 42",
    ])
    assert report[0]["exception"] == "RunnerError"
    assert report[0]["status"] == "errored"
    assert "output limit" in report[0]["outcome"]["exception_msg"]
    assert report[1]["outcome"]["result_repr"] == "42"


def test_closed_output_pipes_do_not_disable_process_timeout():
    proc = subprocess.Popen(
        [sys.executable, "-c", "import os,time; os.close(1); os.close(2); time.sleep(5)"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            dynamic_prober._communicate_bounded(proc, b"", timeout=0.1)
    finally:
        proc.kill()
        proc.wait(timeout=3)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            stream.close()
