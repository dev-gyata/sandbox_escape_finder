"""Quickstart: run both the static analyzer and the dynamic prober.

Usage:
    python examples/quickstart.py

This mirrors the public-API snippet from the task description and prints a
results table (payload x technique x static-flag x dynamic-escape) plus the
false-positive / false-negative summary.
"""

from __future__ import annotations

from sandbox_escape_finder import (
    DynamicProber,
    StaticAnalyzer,
    builtin_payloads,
    canary_oracle,
    false_positive_negative_analysis,
    sandbox_exec,
)

CONFIG = {
    # All six static detectors on; the supplied corpus controls dynamic tests.
    "enabled_techniques": list(__import__("sandbox_escape_finder").KNOWN_TECHNIQUES),
    "static_confidence_threshold": 0.0,
    "subprocess_timeout_s": 10.0,
    "seed": 1234,
}


def main() -> None:
    # ---- Static analysis -------------------------------------------------
    analyzer = StaticAnalyzer(CONFIG)
    source = "().__class__.__bases__[0].__subclasses__()"
    findings = analyzer.scan(source)
    print("Static findings for a classic traversal:")
    for f in findings:
        print(f"  [{f['confidence']:.2f}] {f['technique']}: {f['message']}")

    # ---- Dynamic probing -------------------------------------------------
    prober = DynamicProber(sandbox_exec, canary_oracle, CONFIG)
    report = prober.run(builtin_payloads())

    print("\nDynamic results against RestrictedPython:")
    header = f"{'payload':28} {'technique':32} {'effect':13} {'static':7} {'escaped':8} exc"
    print(header)
    print("-" * len(header))
    for r in report:
        print(
            f"{r['id']:28} {r['technique']:32} {r['effect']:13} "
            f"{str(r['static_flagged']):7} {str(r['escaped']):8} {r['exception']}"
        )

    analysis = false_positive_negative_analysis(report)
    print("\nFalse-positive / false-negative summary:")
    print(f"  counts: {analysis['counts']}")
    print(f"  flagged-but-did-not-escape: {analysis['flagged_no_escape']}")
    print(f"  escaped-but-not-flagged:    {analysis['escaped_not_flagged']}")
    print(
        "\nInterpretation: RestrictedPython blocks every attempt, so "
        "'flagged-but-did-not-escape' is high by design (the analyzer correctly "
        "spots the technique; the sandbox then stops it). 'escaped-but-not-flagged' "
        "is the dangerous column and should be empty."
    )


if __name__ == "__main__":
    main()
