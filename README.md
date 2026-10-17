# sandbox_escape_finder

A static + dynamic **escape-technique finder** for evaluating the robustness of
Python execution sandboxes. The default target is
[RestrictedPython](https://github.com/zopefoundation/RestrictedPython).

> **This is defensive security research.** The tool *evaluates* an existing
> open-source sandbox; it does not attack any live system. Every dynamic test
> runs a payload in a **fresh subprocess** (its own process group, with a
> wall-clock timeout, bounded output, `fd 1` shielded, and best-effort CPU /
> file-size rlimits) whose designated "escape target" is a **canary file in a
> throwaway temp directory** — never a real system path.
>
> **Scope of isolation:** the subprocess hardening protects the *test host*
> against the built-in corpus and ordinary misbehavior; it is **not** a
> kernel-level sandbox. The child still runs with the caller's UID, filesystem
> and network access, so a *genuinely novel OS-level escape* could still reach
> host resources. Run untrusted or unknown payloads inside an OS-enforced
> sandbox / disposable VM. See "Assumptions and limitations".

It has two halves:

1. **`StaticAnalyzer`** — parses arbitrary Python source into an AST and flags
   nodes matching known escape-technique classes, with a source location and a
   confidence score.
2. **`DynamicProber`** — runs an *attributed* corpus of escape payloads against
   a live sandbox and uses an automated **oracle** to decide which payloads
   actually broke out. It then compares the static verdict against the dynamic
   result (the false-positive / false-negative analysis).

---

## Installation

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[test]"
```

Dependencies are pinned in `pyproject.toml` (`RestrictedPython>=7.0,<9.0`;
`pytest` for the test extra). Python ≥ 3.9.

## Quickstart

```python
from sandbox_escape_finder import StaticAnalyzer, DynamicProber

analyzer = StaticAnalyzer(config)
findings = analyzer.scan(source_code)

prober = DynamicProber(sandbox_exec, oracle, config)
report = prober.run(payload_corpus)
```

A runnable version (with the built-in sandbox, oracle, and corpus) is in
[`examples/quickstart.py`](examples/quickstart.py):

```bash
python examples/quickstart.py
```

## Public API

| Name | Type | Meaning |
|------|------|---------|
| `config` | `dict` / JSON | Enabled technique detectors/payload categories, `static_confidence_threshold`, `subprocess_timeout_s`, `seed`, `extra_payloads`. Validated by `load_config`. |
| `source_code` | `str` | Arbitrary Python source to statically vet. |
| `findings` | `list[dict]` | One entry per match: `technique`, `message`, `lineno`/`col_offset` (+ end), `matched_source`, `confidence`. |
| `sandbox_exec` | callable `str -> result` | Thin wrapper around RestrictedPython's documented restricted compile-and-exec. Must be importable at module scope for isolated runs. |
| `oracle` | callable `(pre_state, exec_result, post_state) -> bool` | Automated check for an out-of-sandbox effect. Default: `canary_oracle`. |
| `payload_corpus` | iterable of `Payload`/`dict`/`str` | Candidate payloads, each attributed to a technique. Built-in set via `builtin_payloads()`. |
| `report` | `list[dict]` | Per payload: static verdict, whether it executed, whether the oracle confirmed an escape, timing. |

## Detected technique classes

The analyzer implements six named classes (≥ 5 required). Each finding cites the
technique and the offending AST node's location.

| # | Technique id | What it looks for | Why RestrictedPython does / doesn't stop it |
|---|--------------|-------------------|---------------------------------------------|
| 1 | `subclasses_traversal` | `__subclasses__`, `__bases__`, `__base__`, `__mro__`, `__class__` attribute hops (and the `getattr(x, "__subclasses__")` dynamic form) | **Stopped at compile time**: `compile_restricted` rejects underscore-prefixed attribute names (`SyntaxError`). |
| 2 | `globals_closure_access` | `__globals__`, `func_globals`, `__closure__`, `cell_contents` | **Stopped at compile time** (underscore names rejected). |
| 3 | `builtins_restoration` | the `__builtins__` name; dynamic `getattr` chains | **Stopped**: `__builtins__` name rejected at compile; and `safe_builtins` omits `open`/`eval`/`getattr`. |
| 4 | `frame_generator_introspection` | `gi_frame`, `cr_frame`, `f_globals`, `f_back`, `f_locals`, `__traceback__`, `tb_frame` | Non-underscore names (`gi_frame`, `f_globals`) *are* allowed by `safer_getattr`, but inside the sandbox they only expose the **restricted** globals (whose `__builtins__` is `safe_builtins`), so there is nothing dangerous to reach. Payloads that mix in `__traceback__` are compile-rejected. |
| 5 | `format_string_attribute_access` | `"...{0.__class__}...".format(obj)` — attribute walking via the C-level formatter that bypasses `_getattr_` | **Stopped explicitly**: RestrictedPython raises `NotImplementedError` for `str.format`/`format_map`. (This is a *disclosure* primitive, not code-exec — see the oracle note.) |
| 6 | `import_access` | `import`/`from ... import`, `__import__(...)` | **Stopped**: imports are gated by a guarded `__import__` that denies them (`ImportError`); and `__import__` as a literal name is compile-rejected. |

## Isolation and the oracle

* **Isolation.** `DynamicProber` launches each payload in a fresh
  `python -I -m sandbox_escape_finder._subprocess_runner` child. The child
  imports the same `sandbox_exec` by a `module:qualname` spec and runs one
  payload. A per-payload `subprocess_timeout_s` wall-clock limit kills any
  runaway child (e.g. an infinite loop), which is recorded as a `Timeout`
  (never an escape). A crashing/non-zero child is recorded as a `RunnerError`.
* **Canary oracle.** Before each run the prober snapshots a canary file in a
  `tempfile.TemporaryDirectory`; after the run it snapshots again. `canary_oracle`
  returns `True` iff the canary appeared or its content changed — i.e. the
  restricted code performed real filesystem I/O it should not have been able to.
  The canary path is injected into each payload as a `repr()`'d string literal.

The oracle is validated two ways (see `tests/test_oracle.py`):
* against a **deliberately broken toy sandbox** (`toy_unrestricted_exec`, a plain
  `exec`) where a write payload **must** escape and the oracle **must** catch it;
* against the real RestrictedPython sandbox, where the same payload must be
  blocked.

## Results (full built-in corpus vs. RestrictedPython 8.5)

Produced by `examples/quickstart.py` (payload × technique × static-flag ×
dynamic-escape):

| payload | technique | effect | static flag | escaped | blocked by |
|---------|-----------|--------|:-----------:|:-------:|-----------|
| subclasses_init_globals | subclasses_traversal | canary_write | ✅ | ❌ | SyntaxError (compile) |
| subclasses_catch_warnings | subclasses_traversal | canary_write | ✅ | ❌ | SyntaxError (compile) |
| lambda_globals | globals_closure_access | canary_write | ✅ | ❌ | SyntaxError (compile) |
| closure_cell_contents | globals_closure_access | canary_write | ✅ | ❌ | SyntaxError (compile) |
| builtins_direct | builtins_restoration | canary_write | ✅ | ❌ | SyntaxError (compile) |
| builtins_via_getattr | builtins_restoration | canary_write | ✅ | ❌ | SyntaxError (`.__dict__`) |
| generator_gi_frame | frame_generator_introspection | canary_write | ✅ | ❌ | SyntaxError (compile) |
| traceback_frame | frame_generator_introspection | canary_write | ✅ | ❌ | SyntaxError (compile) |
| format_globals_leak | format_string_attribute_access | disclosure | ✅ | ❌ | NotImplementedError (format guard) |
| import_os_write | import_access | canary_write | ✅ | ❌ | ImportError (import guard) |
| dunder_import_os | import_access | canary_write | ✅ | ❌ | SyntaxError (compile) |

**False-positive / false-negative summary:**
`{total: 11, static_flagged: 11, escaped: 0, blocked: 11, errored: 0, flagged_no_escape: 11, escaped_not_flagged: 0}`

(`blocked` = the sandbox genuinely evaluated and stopped it; `errored` = an
inconclusive run such as a RunnerError/Timeout, kept separate so a broken
environment can't be mistaken for a sandbox that held. Here `errored: 0`.)

Reading this:
* **`escaped_not_flagged == 0`** — the important column. No payload escaped
  without the static analyzer flagging it. (Against the broken toy sandbox, 10
  of the 11 payloads *do* escape, confirming both the payloads and the oracle
  actually work.)
* **`flagged_no_escape == 11`** is **high by design, not a defect.** Each flag is
  a correct *detection of the technique*; RestrictedPython then blocks the
  technique. In a sandbox-robustness study these are "defense held" rows, not
  analyzer errors. The `effect` column distinguishes a true I/O attempt
  (`canary_write`) from a pure information-leak primitive (`disclosure`, the
  `str.format` case) that the canary oracle intentionally does not count as a
  filesystem escape.

### Honest conclusion

With its documented hardened configuration (`compile_restricted` + `safe_builtins`
+ the `Guards`), **RestrictedPython 8.5 blocked every payload in this corpus.**
Its strongest single defense is **compile-time rejection of underscore-prefixed
names**, which kills the classic `__class__ → __subclasses__ → __globals__ →
__builtins__` traversals before they run; `safe_builtins` (no `open`/`getattr`),
the import guard, and the explicit `str.format` guard cover the rest. This is a
negative result for "can we escape it," and — per the task — a valid, expected
finding. The value of the toolbox is the *reproducible, automated* comparison it
produces, which would immediately surface a regression if a future
RestrictedPython change let any `escaped_not_flagged` (or any `escaped`) row
appear.

## Configuration (data-driven)

```python
config = {
    "enabled_techniques": ["subclasses_traversal", "import_access", ...],  # subset of KNOWN_TECHNIQUES
    "static_confidence_threshold": 0.6,   # drop findings below this
    "subprocess_timeout_s": 5.0,          # per-payload wall-clock limit
    "seed": 0,                            # reproducibility
    "extra_payloads": [                   # append your own, attributed
        {"technique": "import_access", "effect": "canary_write", "code": "import os\n..."},
    ],
}
```

Invalid configs fail fast with a `ConfigError` naming the offending key.

### Logging and reproducibility

* The analyzer and prober modules log through the standard `logging` module
  (`logging.getLogger("sandbox_escape_finder...")`). `DynamicProber` logs one
  `INFO` line per payload (id, technique, executed, escaped, exception,
  duration) and the static analyzer logs each finding at `DEBUG`. Enable with
  `logging.basicConfig(level=logging.INFO)`.
* `seed` controls the **execution order** of the corpus (via `random.Random(seed)`),
  so a given seed reproduces the same order and timing; each report row records
  its `exec_order`. The returned report is re-sorted into corpus order so the
  table layout is stable regardless of seed.
* `report` rows also carry `executed` — `True` only if the sandbox actually ran
  the payload body. A compile-time `SyntaxError` (RestrictedPython rejecting the
  source) or a `RunnerError` reads as `executed: False`.

## Tests

```bash
pytest -q
```

Covers: AST detector positive/negative snippets (including dunder-in-a-string
vs. real attribute access), confidence-threshold and technique filtering, the
oracle against the broken toy sandbox fixture, the timeout fallback path,
payload-type normalization, and the end-to-end corpus run against
RestrictedPython.

## Project layout

```
src/sandbox_escape_finder/
├── __init__.py            # public API
├── config.py             # config schema + validation
├── static_analyzer.py    # AST detectors -> findings
├── sandbox.py            # RestrictedPython wrapper + broken toy fixture
├── oracle.py             # canary snapshot + canary_oracle
├── payloads.py           # attributed payload corpus
├── dynamic_prober.py     # isolated runner orchestration + FP/FN analysis
└── _subprocess_runner.py # child-process entry point
tests/                    # pytest suite
examples/quickstart.py    # the snippet above, runnable
```

## Assumptions and limitations

* "Escape" is defined concretely as **real filesystem I/O** (canary touch). A
  pure information-disclosure primitive (e.g. `str.format` attribute walking)
  is detected statically and labeled `disclosure`, but is not counted as a
  filesystem escape by the default oracle. Swap in a different `oracle` to score
  disclosure or other effects.
* Subprocess isolation protects the **test host**, not a true kernel-level
  sandbox; it is sufficient for safely evaluating RestrictedPython payloads but
  is not itself a production sandbox.
* The corpus targets the well-known introspection classes from the cited
  catalogs; it is representative, not exhaustive.
* The static analyzer detects the `str.format` / `str.format_map` attribute-walk
  only when the template is a **string literal**. A template held in a variable
  (`fmt = "{0.__class__}"; fmt.format(o)`) is a known false-negative — resolving
  it would require data-flow analysis beyond this single-pass AST walk.
* Subprocess isolation uses a new process group (`start_new_session=True`),
  SIGKILLs the whole group on timeout with a bounded reap (a grandchild that
  `setsid()`s out of the group can't hang the run), shields `fd 1` so a payload
  can't corrupt the result channel, and applies best-effort CPU / file-size
  rlimits. This hardens the test host but is **not** a kernel-level sandbox: the
  child inherits the caller's UID/filesystem/network, so a genuinely novel
  OS-level escape could still reach host resources. Run unknown payloads in an
  OS-enforced sandbox or disposable VM.
* The canary oracle assumes a "create-and-leave" effect: a payload that creates
  *then deletes* the canary within one run reads as no-escape (detecting it
  would need in-run filesystem watching).
* `executed` is derived from the child's exception type, so a payload that runs
  and then itself raises a *runtime* `SyntaxError` (e.g. via `compile()`) is
  conservatively labeled `executed=False`.
