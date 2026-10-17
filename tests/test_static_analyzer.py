"""Unit tests for the AST static analyzer: known positive and negative snippets."""

from __future__ import annotations

import pytest

from sandbox_escape_finder import StaticAnalyzer
from sandbox_escape_finder.config import ConfigError

# One representative positive snippet per technique class.
POSITIVE_CASES = [
    ("subclasses_traversal", "().__class__.__bases__[0].__subclasses__()"),
    ("globals_closure_access", "(lambda: None).__globals__['__builtins__']"),
    ("globals_closure_access", "f.__closure__[0].cell_contents"),
    ("builtins_restoration", "b = __builtins__"),
    ("frame_generator_introspection", "g().gi_frame.f_globals"),
    ("frame_generator_introspection", "e.__traceback__.tb_frame.f_globals"),
    ("format_string_attribute_access", "'{0.__class__}'.format(object())"),
    ("import_access", "import os"),
    ("import_access", "mod = __import__('os')"),
]

# Benign snippets that must NOT be flagged — these are where regex approaches
# tend to false-positive (dunder inside a string, normal attribute access).
NEGATIVE_CASES = [
    "x = [1, 2, 3]; x.append(4)",
    "d = {}; d['key'] = 42",
    'msg = "please do not touch __class__ directly"  # dunder only in a string',
    "total = sum(i for i in range(10))",
    "user.name = 'alice'",
    "'{0}: {1}'.format(a, b)",  # format without attribute access
]


@pytest.mark.parametrize("technique,code", POSITIVE_CASES)
def test_positive_snippets_are_flagged(technique, code):
    findings = StaticAnalyzer().scan(code)
    techniques = {f["technique"] for f in findings}
    assert technique in techniques, f"expected {technique} for {code!r}, got {techniques}"


@pytest.mark.parametrize("code", NEGATIVE_CASES)
def test_benign_snippets_are_not_flagged(code):
    findings = StaticAnalyzer().scan(code)
    assert findings == [], f"unexpected findings for benign {code!r}: {findings}"


def test_dunder_in_string_is_not_flagged_but_attribute_is():
    """AST (not regex): the same token flags only when it is a real attribute."""
    assert StaticAnalyzer().scan('s = "__globals__"') == []
    assert StaticAnalyzer().scan("s = f.__globals__") != []


def test_getattr_dynamic_form_is_detected():
    findings = StaticAnalyzer().scan("getattr(obj, '__subclasses__')")
    assert any(f["technique"] == "subclasses_traversal" for f in findings)


def test_getattr_keyword_form_is_detected():
    findings = StaticAnalyzer().scan("getattr(obj, name='__globals__')")
    assert any(f["technique"] == "globals_closure_access" for f in findings)


def test_format_map_and_dict_and_vars_are_detected():
    assert any(
        f["technique"] == "format_string_attribute_access"
        for f in StaticAnalyzer().scan("'{0.__class__}'.format_map(d)")
    )
    assert any(
        f["technique"] == "globals_closure_access"
        for f in StaticAnalyzer().scan("ns = obj.__dict__")
    )
    assert any(
        f["technique"] == "globals_closure_access"
        for f in StaticAnalyzer().scan("ns = vars(obj)")
    )


def _techs(code):
    return {f["technique"] for f in StaticAnalyzer().scan(code)}


def test_format_detector_field_parsing():
    # Nested replacement field inside a format spec must be detected.
    assert "format_string_attribute_access" in _techs("'{0:{1.__class__}}'.format(0, object())")
    # Sensitive item traversal must be detected.
    assert "format_string_attribute_access" in _techs("'{0[__builtins__][open]}'.format(g)")
    # A dict-key lookup that merely contains a dot is NOT an attribute walk.
    assert _techs("'{0[a.b]}'.format(d)") == set()
    # A benign (non-underscore) attribute is not flagged.
    assert _techs("'{0.name}'.format(user)") == set()


def test_builtins_restoration_attribute_and_getattr_forms():
    assert "builtins_restoration" in _techs("y = x.__builtins__")
    assert "builtins_restoration" in _techs("getattr(x, '__builtins__')")


def test_scan_safe_swallows_nonsyntax_errors():
    # A pathologically deep attribute chain makes ast.parse raise RecursionError;
    # scan_safe must still return [] rather than propagating.
    deep = "a" + ".b" * 20000
    assert StaticAnalyzer().scan_safe(deep) == []


def test_finding_has_location_and_source():
    findings = StaticAnalyzer().scan("x = f.__globals__")
    assert findings, "expected at least one finding"
    f = findings[0]
    assert f["lineno"] == 1
    assert f["col_offset"] >= 0
    assert "__globals__" in f["matched_source"]
    assert 0.0 <= f["confidence"] <= 1.0


def test_confidence_threshold_filters_low_confidence():
    code = "x = ().__class__"  # __class__ alone is low confidence (0.5)
    assert StaticAnalyzer({"static_confidence_threshold": 0.0}).scan(code)
    assert StaticAnalyzer({"static_confidence_threshold": 0.9}).scan(code) == []


def test_enabled_techniques_filter():
    code = "import os"
    assert StaticAnalyzer({"enabled_techniques": ["import_access"]}).scan(code)
    assert StaticAnalyzer({"enabled_techniques": ["subclasses_traversal"]}).scan(code) == []


def test_syntax_error_propagates_but_scan_safe_swallows():
    with pytest.raises(SyntaxError):
        StaticAnalyzer().scan("def (:")
    assert StaticAnalyzer().scan_safe("def (:") == []


def test_invalid_config_rejected():
    with pytest.raises(ConfigError):
        StaticAnalyzer({"enabled_techniques": ["not_a_real_technique"]})
    with pytest.raises(ConfigError):
        StaticAnalyzer({"static_confidence_threshold": 5})


def test_config_rejects_bool_for_numeric_fields():
    # bool is a subtype of int; it must not slip through numeric/seed validation.
    with pytest.raises(ConfigError):
        StaticAnalyzer({"static_confidence_threshold": True})
    with pytest.raises(ConfigError):
        StaticAnalyzer({"seed": True})
