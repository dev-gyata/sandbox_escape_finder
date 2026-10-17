"""Configuration schema, defaults, and validation.

Configuration is intentionally data-driven: every knob lives in a plain
JSON-serialisable ``dict`` so a run can be reproduced from a saved config file.
This module validates that dict and fills in defaults, failing loudly (with a
clear message) on malformed input rather than silently doing the wrong thing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# The canonical list of technique identifiers this toolbox understands. Keeping
# it in one place lets both the static detectors and the config validator agree
# on the vocabulary.
KNOWN_TECHNIQUES: tuple[str, ...] = (
    "subclasses_traversal",
    "globals_closure_access",
    "builtins_restoration",
    "frame_generator_introspection",
    "format_string_attribute_access",
    "import_access",
)


class ConfigError(ValueError):
    """Raised when a user-supplied config dict is invalid."""


@dataclass(frozen=True)
class Config:
    """Validated configuration for the static analyzer and dynamic prober.

    Attributes:
        enabled_techniques: Which technique detectors / payload categories are
            active. Defaults to all known techniques.
        static_confidence_threshold: Findings below this confidence are dropped
            from :meth:`StaticAnalyzer.scan` output (0.0 keeps everything).
        subprocess_timeout_s: Hard wall-clock limit for each sandboxed payload
            run, after which the child process is killed and recorded as a
            timeout. Protects the test suite from an infinite-loop payload.
        seed: Seed used wherever ordering/randomness could otherwise vary, so
            runs are reproducible.
        extra_payloads: Additional ``{"technique": ..., "code": ...}`` payloads
            to append to the built-in corpus.
    """

    enabled_techniques: frozenset[str] = frozenset(KNOWN_TECHNIQUES)
    static_confidence_threshold: float = 0.0
    subprocess_timeout_s: float = 5.0
    seed: int = 0
    extra_payloads: tuple[dict[str, str], ...] = field(default_factory=tuple)


def load_config(config: dict[str, Any] | None) -> Config:
    """Validate ``config`` and return a frozen :class:`Config`.

    Args:
        config: User-supplied dict, or ``None`` for all defaults.

    Returns:
        A validated :class:`Config`.

    Raises:
        ConfigError: If any field has the wrong type or an out-of-range value.
    """
    if config is None:
        return Config()
    if not isinstance(config, dict):
        raise ConfigError(f"config must be a dict or None, got {type(config).__name__}")

    unknown = set(config) - {
        "enabled_techniques",
        "static_confidence_threshold",
        "subprocess_timeout_s",
        "seed",
        "extra_payloads",
    }
    if unknown:
        raise ConfigError(f"unknown config keys: {sorted(unknown)}")

    techniques = config.get("enabled_techniques", list(KNOWN_TECHNIQUES))
    if not isinstance(techniques, (list, tuple, set, frozenset)):
        raise ConfigError("enabled_techniques must be a list of technique names")
    techniques = frozenset(techniques)
    bad = techniques - set(KNOWN_TECHNIQUES)
    if bad:
        raise ConfigError(
            f"unknown techniques {sorted(bad)}; known: {sorted(KNOWN_TECHNIQUES)}"
        )
    if not techniques:
        raise ConfigError("enabled_techniques must not be empty")

    threshold = config.get("static_confidence_threshold", 0.0)
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not (0.0 <= threshold <= 1.0)
    ):
        raise ConfigError("static_confidence_threshold must be a float in [0.0, 1.0]")

    timeout = config.get("subprocess_timeout_s", 5.0)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise ConfigError("subprocess_timeout_s must be a positive number")

    seed = config.get("seed", 0)
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ConfigError("seed must be an int")

    extra = config.get("extra_payloads", [])
    if not isinstance(extra, (list, tuple)):
        raise ConfigError("extra_payloads must be a list")
    norm_extra: list[dict[str, str]] = []
    for i, p in enumerate(extra):
        if not isinstance(p, dict) or "technique" not in p or "code" not in p:
            raise ConfigError(
                f"extra_payloads[{i}] must be a dict with 'technique' and 'code' keys"
            )
        if p["technique"] not in KNOWN_TECHNIQUES:
            raise ConfigError(
                f"extra_payloads[{i}].technique '{p['technique']}' is not a known technique"
            )
        # Preserve optional attribution metadata (id, effect) so it survives
        # into the report instead of being silently reset to defaults.
        norm = {"technique": str(p["technique"]), "code": str(p["code"])}
        if "id" in p:
            norm["id"] = str(p["id"])
        if "effect" in p:
            norm["effect"] = str(p["effect"])
        norm_extra.append(norm)

    return Config(
        enabled_techniques=techniques,
        static_confidence_threshold=float(threshold),
        subprocess_timeout_s=float(timeout),
        seed=seed,
        extra_payloads=tuple(norm_extra),
    )
