"""Thin wrappers around RestrictedPython's documented restricted-exec setup.

This module provides two execution primitives with the *same* signature
``code: str -> result``:

* :func:`sandbox_exec` — the real target under test. It builds a restricted
  global namespace the way RestrictedPython's documentation prescribes
  (``compile_restricted`` + ``safe_globals`` + the ``Guards`` helpers, crucially
  ``safer_getattr`` which blocks access to underscore-prefixed attributes) and
  executes the supplied code inside it. This is the sandbox whose robustness we
  are evaluating — we do not modify it.

* :func:`toy_unrestricted_exec` — a deliberately broken "sandbox" used only as a
  test fixture. It runs code with a plain ``exec`` and no restrictions, so any
  escape payload trivially succeeds. The oracle must flag it; that is how we
  test the oracle itself.

Both are module-level functions so the out-of-process runner can import them by
a ``"module:qualname"`` spec.
"""

from __future__ import annotations

from RestrictedPython import compile_restricted, safe_builtins, safe_globals
from RestrictedPython.Eval import default_guarded_getitem, default_guarded_getiter
from RestrictedPython.Guards import (
    full_write_guard,
    guarded_iter_unpack_sequence,
    guarded_unpack_sequence,
    safer_getattr,
)
from RestrictedPython.PrintCollector import PrintCollector


def _build_restricted_globals() -> dict:
    """Construct the restricted global namespace per RestrictedPython docs.

    RestrictedPython defends in several distinct layers, which the dynamic
    results make visible:

    * **Compile-time name rejection.** ``compile_restricted`` runs a
      ``RestrictingNodeTransformer`` that raises ``SyntaxError`` for any
      underscore-prefixed attribute or variable (``__class__``, ``__globals__``,
      ``__subclasses__`` via a literal, ``__builtins__`` ...). This blocks the
      classic dunder traversals before they ever run.
    * **Reduced builtins.** ``safe_builtins`` omits ``open``, ``eval``, ``exec``
      and even ``getattr``, so a payload cannot call them even if it reaches
      their name; ``__import__`` is replaced by a guard that denies imports.
    * **Explicit ``str.format`` guard.** RestrictedPython raises
      ``NotImplementedError`` for ``str.format``/``format_map`` because the
      C-level formatter would otherwise walk attributes outside ``_getattr_``.
    * **Runtime guards.** ``safer_getattr`` (wired as ``_getattr_``) refuses
      underscore attribute access for any name that *did* reach runtime (e.g.
      via a non-literal), and ``default_guarded_getitem`` /
      ``default_guarded_getiter`` guard subscription and iteration.
    """
    glb = dict(safe_globals)  # {'__builtins__': safe_builtins}
    glb["__builtins__"] = dict(safe_builtins)
    glb.update(
        {
            "_getattr_": safer_getattr,
            "_getitem_": default_guarded_getitem,
            "_getiter_": default_guarded_getiter,
            "_write_": full_write_guard,
            "_unpack_sequence_": guarded_unpack_sequence,
            "_iter_unpack_sequence_": guarded_iter_unpack_sequence,
            "_print_": PrintCollector,
            "__name__": "restricted_module",
            "__metaclass__": type,
        }
    )
    return glb


def sandbox_exec(code: str):
    """Compile and execute ``code`` inside a RestrictedPython sandbox.

    Args:
        code: Python source to run under restriction.

    Returns:
        The restricted namespace's ``result`` variable if the code assigned one,
        otherwise ``None``.

    Raises:
        SyntaxError: If ``compile_restricted`` rejects the source (disallowed
            syntax is itself a restriction and is reported honestly).
        Exception: Whatever the restricted code raises at runtime (e.g. a
            ``NameError`` for a builtin that was removed, or an error from
            ``safer_getattr`` when underscore attribute access is attempted).
    """
    byte_code = compile_restricted(code, filename="<sandbox>", mode="exec")
    glb = _build_restricted_globals()
    exec(byte_code, glb)  # noqa: S102 - executing restricted bytecode is the point
    return glb.get("result")


def toy_unrestricted_exec(code: str):
    """A BROKEN sandbox used only as a test fixture — never for real use.

    Runs ``code`` with an unrestricted ``exec``. Any escape payload will succeed,
    which lets us assert that the oracle correctly reports an escape.
    """
    glb: dict = {"__name__": "toy_unrestricted"}
    exec(code, glb)  # noqa: S102 - intentionally unrestricted test fixture
    return glb.get("result")
