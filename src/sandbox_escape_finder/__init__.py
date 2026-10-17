"""sandbox_escape_finder — static + dynamic escape-technique finder.

A defensive-security research toolbox for evaluating the robustness of Python
execution sandboxes (default target: RestrictedPython):

* :class:`StaticAnalyzer` — AST-based detection of known escape-technique
  classes in arbitrary source.
* :class:`DynamicProber` — runs an attributed payload corpus against a live
  sandbox in isolated subprocesses and reports which payloads actually escape.
* :func:`canary_oracle` — default automated escape oracle (canary-file touch).
* :func:`builtin_payloads` — the built-in attributed payload corpus.
* :func:`sandbox_exec` — thin RestrictedPython wrapper (the sandbox under test).

See the task README for the method write-up and results table.
"""

from __future__ import annotations

from .config import KNOWN_TECHNIQUES, Config, ConfigError, load_config
from .dynamic_prober import DynamicProber, false_positive_negative_analysis
from .oracle import canary_oracle, snapshot_canary
from .payloads import Payload, builtin_payloads
from .sandbox import sandbox_exec, toy_unrestricted_exec
from .static_analyzer import Finding, StaticAnalyzer

__all__ = [
    "StaticAnalyzer",
    "Finding",
    "DynamicProber",
    "false_positive_negative_analysis",
    "canary_oracle",
    "snapshot_canary",
    "Payload",
    "builtin_payloads",
    "sandbox_exec",
    "toy_unrestricted_exec",
    "Config",
    "ConfigError",
    "load_config",
    "KNOWN_TECHNIQUES",
]

__version__ = "0.1.0"
