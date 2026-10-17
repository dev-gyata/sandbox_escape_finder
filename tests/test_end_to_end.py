"""End-to-end: run the full built-in corpus against real RestrictedPython."""

from __future__ import annotations

from sandbox_escape_finder import (
    DynamicProber,
    StaticAnalyzer,
    builtin_payloads,
    canary_oracle,
    false_positive_negative_analysis,
    sandbox_exec,
)


def test_full_corpus_against_restrictedpython():
    corpus = builtin_payloads()
    assert len(corpus) >= 10, "task requires at least 10 attributed payloads"

    # Static pass: every payload template should be flagged by the analyzer.
    analyzer = StaticAnalyzer()
    for p in corpus:
        rendered = p.render("/tmp/throwaway_canary")
        findings = analyzer.scan_safe(rendered)
        assert findings, f"payload {p.id} was not statically flagged"

    # Dynamic pass against the real sandbox.
    prober = DynamicProber(sandbox_exec, canary_oracle, {"subprocess_timeout_s": 10})
    report = prober.run(corpus)
    assert len(report) == len(corpus)

    # RestrictedPython should block every escape attempt: no canary written.
    escaped = [r["id"] for r in report if r["escaped"]]
    assert escaped == [], f"unexpected escapes against RestrictedPython: {escaped}"

    # No row should be inconclusive (RunnerError/Timeout): a broken execution
    # environment must not masquerade as "the sandbox blocked everything".
    errored = [r["id"] for r in report if r["status"] == "errored"]
    assert errored == [], f"inconclusive runs (env broken?): {errored}"
    # Every payload should have been genuinely evaluated by the sandbox.
    assert all(r["status"] in ("escaped", "blocked") for r in report)

    analysis = false_positive_negative_analysis(report)
    assert analysis["counts"]["total"] == len(corpus)
    assert analysis["counts"]["escaped_not_flagged"] == 0
    assert analysis["counts"]["errored"] == 0


def test_at_least_five_distinct_techniques_present():
    techniques = {p.technique for p in builtin_payloads()}
    assert len(techniques) >= 5, f"need >=5 technique classes, got {techniques}"
