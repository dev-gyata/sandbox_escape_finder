"""AST-based static analyzer for known Python sandbox-escape technique classes.

The analyzer parses source into an abstract syntax tree (``ast``) and walks it
once, letting a set of *detectors* flag nodes that match a known escape
technique. We deliberately work on the AST rather than regexes: a regex cannot
tell ``foo.__globals__`` (a real attribute access) from the string literal
``"__globals__"`` inside an unrelated comment or message, whereas the AST makes
the node's role explicit.

Each detector reports a :class:`Finding` carrying the technique name, the exact
source location of the offending node, the matched source text, and a
confidence score. Confidence encodes how specific the pattern is to an escape
attempt (a ``__subclasses__()`` call is almost always an escape probe; a bare
``__class__`` access is a weaker, more ambiguous signal).
"""

from __future__ import annotations

import ast
import logging
from dataclasses import asdict, dataclass
from typing import Optional

logger = logging.getLogger(__name__)

from .config import Config, load_config

# Attribute names grouped by the technique class they most strongly indicate.
# Each entry maps an attribute name -> (technique, confidence, human message).
_ATTRIBUTE_SIGNATURES: dict[str, tuple[str, float, str]] = {
    # --- Technique 1: __subclasses__ / type-graph traversal ---------------
    "__subclasses__": (
        "subclasses_traversal",
        0.95,
        "Calls object.__subclasses__() to walk the type graph toward os/subprocess.",
    ),
    "__bases__": (
        "subclasses_traversal",
        0.80,
        "Reads __bases__ to climb the class hierarchy toward object.",
    ),
    "__base__": (
        "subclasses_traversal",
        0.80,
        "Reads __base__ to climb the class hierarchy toward object.",
    ),
    "__mro__": (
        "subclasses_traversal",
        0.80,
        "Reads __mro__ to reach a base class such as object.",
    ),
    "__class__": (
        "subclasses_traversal",
        0.50,
        "Reads __class__, the usual first hop of a __subclasses__ traversal.",
    ),
    # --- Technique 2: __globals__ / __closure__ access --------------------
    "__globals__": (
        "globals_closure_access",
        0.90,
        "Reads a function's __globals__ to reach module-level names/builtins.",
    ),
    "func_globals": (
        "globals_closure_access",
        0.90,
        "Reads func_globals (py2-style) to reach the defining module globals.",
    ),
    "__closure__": (
        "globals_closure_access",
        0.85,
        "Reads __closure__ to recover values captured by a closure.",
    ),
    "cell_contents": (
        "globals_closure_access",
        0.85,
        "Reads cell_contents to extract a value out of a closure cell.",
    ),
    "__dict__": (
        "globals_closure_access",
        0.60,
        "Reads __dict__ to reach a module/class namespace (e.g. to recover open).",
    ),
    # --- Technique 3 (attribute form): __builtins__ restoration -----------
    "__builtins__": (
        "builtins_restoration",
        0.90,
        "Reads a __builtins__ attribute to recover removed builtins (e.g. open).",
    ),
    # --- Technique 4: frame / generator introspection --------------------
    "gi_frame": (
        "frame_generator_introspection",
        0.85,
        "Reads a generator's gi_frame to reach frame globals.",
    ),
    "gi_code": ("frame_generator_introspection", 0.80, "Reads a generator's gi_code."),
    "cr_frame": (
        "frame_generator_introspection",
        0.85,
        "Reads a coroutine's cr_frame to reach frame globals.",
    ),
    "f_globals": (
        "frame_generator_introspection",
        0.90,
        "Reads frame.f_globals to reach the defining module globals.",
    ),
    "f_back": (
        "frame_generator_introspection",
        0.85,
        "Walks frame.f_back to reach a caller's frame.",
    ),
    "f_locals": (
        "frame_generator_introspection",
        0.80,
        "Reads frame.f_locals to inspect another frame's locals.",
    ),
    "__traceback__": (
        "frame_generator_introspection",
        0.85,
        "Uses an exception __traceback__ to reach a frame object.",
    ),
    "tb_frame": (
        "frame_generator_introspection",
        0.85,
        "Reads tb_frame off a traceback to reach a frame object.",
    ),
}

# Names (not attributes) that are themselves escape signals.
_NAME_SIGNATURES: dict[str, tuple[str, float, str]] = {
    "__builtins__": (
        "builtins_restoration",
        0.90,
        "References __builtins__ to recover removed builtins (e.g. open/eval).",
    ),
    "__import__": (
        "import_access",
        0.85,
        "Calls __import__ directly to load a module such as os.",
    ),
}


@dataclass(frozen=True)
class Finding:
    """One static-analysis hit.

    Attributes:
        technique: One of :data:`config.KNOWN_TECHNIQUES`.
        message: Human-readable explanation of why this node was flagged.
        lineno / col_offset: 1-based line and 0-based column of the node start.
        end_lineno / end_col_offset: End position (may be ``None`` on very old
            Python, but populated on all supported versions).
        matched_source: The exact source text of the flagged node.
        confidence: Float in [0, 1]; higher = more specific to an escape pattern,
            not a probability of successful escape.
        node_type: AST class name, e.g. ``Attribute`` or ``Call``.
        matched_node: ``ast.dump`` of the matched node, without location fields.
            Both AST fields default to empty strings for legacy construction.
    """

    technique: str
    message: str
    lineno: int
    col_offset: int
    end_lineno: Optional[int]
    end_col_offset: Optional[int]
    matched_source: str
    confidence: float
    node_type: str = ""
    matched_node: str = ""

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dict of this finding."""
        return asdict(self)


class _Visitor(ast.NodeVisitor):
    """Walks the tree once and accumulates findings."""

    def __init__(self, source: str, enabled: frozenset[str]) -> None:
        self._source = source
        self._enabled = enabled
        self.findings: list[Finding] = []

    # -- helpers ----------------------------------------------------------
    def _segment(self, node: ast.AST) -> str:
        seg = ast.get_source_segment(self._source, node)
        return seg if seg is not None else "<source unavailable>"

    def _add(self, node: ast.AST, technique: str, confidence: float, message: str) -> None:
        if technique not in self._enabled:
            return
        self.findings.append(
            Finding(
                technique=technique,
                message=message,
                lineno=getattr(node, "lineno", -1),
                col_offset=getattr(node, "col_offset", -1),
                end_lineno=getattr(node, "end_lineno", None),
                end_col_offset=getattr(node, "end_col_offset", None),
                matched_source=self._segment(node),
                confidence=confidence,
                node_type=type(node).__name__,
                matched_node=ast.dump(node, include_attributes=False),
            )
        )

    def _check_attr_name(self, node: ast.AST, attr: str) -> None:
        sig = _ATTRIBUTE_SIGNATURES.get(attr)
        if sig is not None:
            technique, confidence, message = sig
            self._add(node, technique, confidence, message)

    # -- visitors ---------------------------------------------------------
    def visit_Attribute(self, node: ast.Attribute) -> None:
        self._check_attr_name(node, node.attr)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        sig = _NAME_SIGNATURES.get(node.id)
        if sig is not None:
            technique, confidence, message = sig
            self._add(node, technique, confidence, message)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._check_call(node)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        names = ", ".join(a.name for a in node.names)
        self._add(
            node,
            "import_access",
            0.80,
            f"Uses an import statement ({names}); RestrictedPython gates imports via __import__.",
        )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self._add(
            node,
            "import_access",
            0.80,
            f"Uses 'from {node.module or '.'} import ...'; imports are gated in restricted mode.",
        )
        self.generic_visit(node)

    # -- call analysis ----------------------------------------------------
    def _check_call(self, node: ast.Call) -> None:
        func = node.func

        # getattr(obj, "__globals__") — dynamic attribute access by name. Handle
        # both the second-positional form and the keyword form
        # getattr(obj, name="__globals__").
        if isinstance(func, ast.Name) and func.id == "getattr":
            name_arg = node.args[1] if len(node.args) >= 2 else None
            if name_arg is None:
                for kw in node.keywords:
                    if kw.arg == "name":
                        name_arg = kw.value
                        break
            if isinstance(name_arg, ast.Constant) and isinstance(name_arg.value, str):
                sig = _ATTRIBUTE_SIGNATURES.get(name_arg.value)
                if sig is not None:
                    technique, confidence, message = sig
                    self._add(
                        node,
                        technique,
                        confidence,
                        f"getattr(..., {name_arg.value!r}): dynamic form of {message}",
                    )

        # vars(obj) — equivalent to obj.__dict__, a namespace-walking primitive.
        if isinstance(func, ast.Name) and func.id == "vars" and node.args:
            self._add(
                node,
                "globals_closure_access",
                0.60,
                "vars(...) returns an object's __dict__ namespace (open/builtins pivot).",
            )

        # "...{0.__class__}...".format(obj) / .format_map(d) — reaching
        # attributes via the C-level formatter. Detected when the template is a
        # string literal; a template held in a variable is a known limitation.
        if (
            isinstance(func, ast.Attribute)
            and func.attr in ("format", "format_map")
            and isinstance(func.value, ast.Constant)
            and isinstance(func.value.value, str)
        ):
            template = func.value.value
            if _format_template_reaches_attributes(template):
                self._add(
                    node,
                    "format_string_attribute_access",
                    0.90,
                    f"str.{func.attr} template reaches a dunder attribute/namespace "
                    "key (e.g. {0.__class__}) to pivot without an explicit attribute node.",
                )


def _format_template_reaches_attributes(template: str, _depth: int = 0) -> bool:
    """Return True if a format template navigates to a *sensitive* name via a
    replacement field, e.g. ``{0.__class__}``, ``{x.__init__.__globals__}``, or
    the item-traversal form ``{0[__builtins__][open]}``.

    We parse each replacement field with
    :func:`_string.formatter_field_name_split` so we can tell an attribute hop
    (``.__class__``) from a dictionary-key lookup (``[a.b]``). This avoids the
    naive "contains a dot" check, which both false-positives on ``{0[a.b]}``
    (a key containing a dot) and misses item traversal. Nested replacement
    fields inside a format spec (``{0:{1.__class__}}``) are inspected
    recursively, with a small depth bound.

    A benign attribute like ``{0.name}`` is *not* flagged — only underscore /
    dunder attributes and underscore/dunder item keys are treated as escape
    signals.
    """
    import _string  # CPython helper backing str.format field parsing
    import string

    if _depth > 5:
        return False
    try:
        for _literal, field_name, spec, _conv in string.Formatter().parse(template):
            if field_name:
                _first, rest = _string.formatter_field_name_split(field_name)
                for is_attr, key in rest:
                    if is_attr and isinstance(key, str) and key.startswith("_"):
                        return True  # attribute hop into a dunder/underscore name
                    if (not is_attr) and isinstance(key, str) and key.startswith("__"):
                        return True  # item lookup of a dunder namespace key
            if spec and _format_template_reaches_attributes(spec, _depth + 1):
                return True
    except (ValueError, AttributeError):
        # Malformed template; be conservative and do not flag.
        return False
    return False


class StaticAnalyzer:
    """Scans Python source for suspected sandbox-escape technique usage.

    Example:
        >>> analyzer = StaticAnalyzer({"static_confidence_threshold": 0.6})
        >>> findings = analyzer.scan("().__class__.__bases__[0].__subclasses__()")
        >>> findings[0]["technique"]
        'subclasses_traversal'
    """

    def __init__(self, config: dict | Config | None = None) -> None:
        self._config = config if isinstance(config, Config) else load_config(config)

    def scan(self, source_code: str) -> list[dict]:
        """Statically analyze ``source_code``.

        Args:
            source_code: Arbitrary Python source to vet.

        Returns:
            A list of finding dicts (see :meth:`Finding.to_dict`), sorted by
            source position then descending confidence, filtered to the enabled
            techniques and the configured confidence threshold.

        Raises:
            SyntaxError: If ``source_code`` cannot be parsed. (Unparseable code
                cannot run in the sandbox either, so surfacing the error is the
                honest behavior.)
        """
        tree = ast.parse(source_code)
        visitor = _Visitor(source_code, self._config.enabled_techniques)
        visitor.visit(tree)

        # Deduplicate identical (technique, position) hits that different
        # visitors may both produce, keeping the highest-confidence message.
        best: dict[tuple, Finding] = {}
        for f in visitor.findings:
            if f.confidence < self._config.static_confidence_threshold:
                continue
            key = (f.technique, f.lineno, f.col_offset)
            if key not in best or f.confidence > best[key].confidence:
                best[key] = f

        ordered = sorted(
            best.values(),
            key=lambda f: (f.lineno, f.col_offset, -f.confidence),
        )
        for f in ordered:
            logger.debug(
                "finding %s@%d:%d conf=%.2f %r",
                f.technique,
                f.lineno,
                f.col_offset,
                f.confidence,
                f.matched_source,
            )
        return [f.to_dict() for f in ordered]

    def scan_safe(self, source_code: str) -> list[dict]:
        """Like :meth:`scan`, but return ``[]`` instead of raising when the
        source cannot be analyzed.

        The dynamic prober scans each payload *in the parent process* before
        isolating it, so any analyzer failure here would abort the whole corpus
        run. A `SyntaxError` is the common case, but a hostile payload can also
        trigger `RecursionError` (a deeply nested attribute chain),
        `UnicodeError` / `ValueError` (e.g. a lone surrogate), or `MemoryError`
        while parsing. We therefore swallow any `Exception` (not
        `BaseException`, so `KeyboardInterrupt`/`SystemExit` still propagate) and
        treat an unanalyzable payload as "no static findings".
        """
        try:
            return self.scan(source_code)
        except Exception:  # noqa: BLE001 - analyzer must never abort the corpus
            logger.warning("static analysis failed for a payload; treating as unflagged")
            return []
