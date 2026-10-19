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
> **Scope of isolation:** a subprocess alone is not a security boundary: it
> inherits the caller's UID, filesystem permissions, and network access. Use
> `sh scripts/evaluate.sh` below to run the entire evaluation in a disposable,
> restricted container, including the deliberately unrestricted test fixture.
> Containers depend on the host kernel and runtime; they do not establish
> universal sandbox security. See "Assumptions and limitations".

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

Dependencies are pinned in `pyproject.toml`: `RestrictedPython==8.5` and
`pytest==8.4.2` for the test extra. Python >=3.10,<3.16, matching the pinned
RestrictedPython release. Isolated dynamic probing uses POSIX process groups
and selectable pipes (for example, macOS or Linux).

## Containerized evaluation (recommended)

Start Docker Desktop or OrbStack, then run from the repository root:

```bash
sh scripts/evaluate.sh
```

The image performs a fresh `pip install -e '.[test]'` and `pip check` during
build. Dependency downloads require network access at build time. At runtime,
the script runs boundary checks, the full test suite, then the quickstart,
stopping on any failure. It prints the image ID and actual Python,
RestrictedPython, and pytest versions.

Evaluation runs as UID 10001, with networking disabled, a read-only root
filesystem, and a 128 MiB writable `/tmp`. It drops all Linux capabilities,
enables `no-new-privileges`, and limits the container to 128 processes, 512 MiB
of memory with no extra swap allowance, and two CPUs. The container is removed
afterward. No host directories or Docker socket are mounted by the script.
The Docker build context includes only solution inputs; local tutorials,
task notes, virtual environments, and Git metadata are excluded.

The Python API still uses one subprocess per payload inside that container.
Calling the API directly on the host does **not** automatically enable Docker.
For genuinely hostile workloads, use a disposable VM appropriate to your threat
model; container boundaries share a kernel with the Docker host.

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
| `config` | `dict` / JSON | Enabled static detectors, `static_confidence_threshold`, `subprocess_timeout_s`, `seed`, `extra_payloads`. Validated by `load_config`. Detector selection does not filter the supplied dynamic corpus. |
| `source_code` | `str` | Arbitrary Python source to statically vet. |
| `findings` | `list[dict]` | One entry per match: `technique`, `message`, `lineno`/`col_offset` (+ end), `matched_source`, `confidence`, `node_type`, `matched_node`. |
| `sandbox_exec` | callable `str -> result` | Thin wrapper around RestrictedPython's documented restricted compile-and-exec. Must be importable at module scope for isolated runs. |
| `oracle` | callable `(pre_state, exec_result, post_state) -> bool` | Automated check for an out-of-sandbox effect. Default: `canary_oracle`. |
| `payload_corpus` | iterable of `Payload`/`dict`/`str` | Candidate payloads, each attributed to a technique. Built-in set via `builtin_payloads()`. |
| `report` | `list[dict]` | Per payload: static verdict, whether it executed, whether the oracle confirmed an escape, timing. |

## Detected technique classes

The analyzer implements six named classes (≥ 5 required). Each finding cites the
technique, source text, location, AST class name (`node_type`), and the matched
AST subtree as an `ast.dump(..., include_attributes=False)` string
(`matched_node`). Findings remain JSON-serializable. These two fields have empty
string defaults when constructing `Finding` using its original arguments.

Confidence scores measure **pattern specificity**, not the probability of a
successful escape. A highly specific escape pattern can still be blocked by
the sandbox. AST dump details can differ between Python versions.

| # | Technique id | What it looks for | Why RestrictedPython does / doesn't stop it |
|---|--------------|-------------------|---------------------------------------------|
| 1 | `subclasses_traversal` | `__subclasses__`, `__bases__`, `__base__`, `__mro__`, `__class__` attribute hops (and the `getattr(x, "__subclasses__")` dynamic form) | **Stopped at compile time**: `compile_restricted` rejects underscore-prefixed attribute names (`SyntaxError`). |
| 2 | `globals_closure_access` | `__globals__`, `func_globals`, `__closure__`, `cell_contents` | **Stopped at compile time** (underscore names rejected). |
| 3 | `builtins_restoration` | the `__builtins__` name; dynamic `getattr` chains | **Stopped**: `__builtins__` name rejected at compile; and `safe_builtins` omits `open`/`eval`/`getattr`. |
| 4 | `frame_generator_introspection` | `gi_frame`, `cr_frame`, `f_globals`, `f_back`, `f_locals`, `__traceback__`, `tb_frame` | **Stopped**: the compiler rejects known inspection attributes such as `gi_frame` and `f_globals`; `safer_getattr` also forbids these names at runtime. Underscore attributes such as `__traceback__` are compile-rejected too. |
| 5 | `format_string_attribute_access` | `"...{0.__class__}...".format(obj)` — attribute walking via the C-level formatter that bypasses `_getattr_` | **Stopped explicitly**: RestrictedPython raises `NotImplementedError` for `str.format`/`format_map`. (This is a *disclosure* primitive, not code-exec — see the oracle note.) |
| 6 | `import_access` | `import`/`from ... import`, `__import__(...)` | **Stopped**: no `__import__` hook is supplied, so import statements raise `ImportError: __import__ not found`; direct use of the literal name `__import__` is compile-rejected. |

## Isolation and the oracle

* **Isolation.** `DynamicProber` launches each payload in a fresh
  `python -I -m sandbox_escape_finder._subprocess_runner` child. The child
  imports the same `sandbox_exec` by a `module:qualname` spec and runs one
  payload. A per-payload `subprocess_timeout_s` wall-clock limit kills any
  runaway child (e.g. an infinite loop), which is recorded as a `Timeout`.
  Missing or malformed child outcomes are recorded as a `RunnerError`; a valid
  outcome is retained even if the child later exits nonzero. The canary oracle
  still runs after errors and timeouts, so an already-observed effect can count
  as an escape.
* **Output budgets.** Python stdout capture and each restricted print collector
  retain only their first 2,000 characters as output arrives. The parent's pipe
  collector retains at most 64 KiB for each of stdout and stderr. Exceeding a
  pipe budget terminates the process group and records a `RunnerError`, keeping
  the experiment inconclusive unless the oracle observes a canary effect.
  These are capture limits, not a general memory limit: code can still allocate
  a large object before printing or returning it.
* **Canary oracle.** Before each run the prober snapshots a canary file in a
  `tempfile.TemporaryDirectory`; after the run it snapshots again. `canary_oracle`
  returns `True` when the canary appears, its fingerprint changes, or a new
  irregular object (such as a symlink) appears at its path — evidence of real
  filesystem activity the restricted code should not have been able to perform.
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
| import_os_write | import_access | canary_write | ✅ | ❌ | ImportError (missing import hook) |
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
the missing import hook, and the explicit `str.format` guard cover the rest. This is a
negative result for "can we escape it," and — per the task — a valid, expected
finding. The value of the toolbox is the *reproducible, automated* comparison it
produces, which would immediately surface a regression if a future
RestrictedPython change let any `escaped_not_flagged` (or any `escaped`) row
appear.

Successful blocking of these 11 candidates does not prove universal sandbox
security; it establishes only the observed result for this corpus, wrapper,
oracle, and dependency version.

## Configuration (data-driven)

```python
config = {
    "enabled_techniques": ["subclasses_traversal", "import_access"],  # static detectors only
    "static_confidence_threshold": 0.6,   # drop findings below this
    "subprocess_timeout_s": 5.0,          # per-payload wall-clock limit
    "seed": 0,                            # reproducibility
    "extra_payloads": [                   # append your own, attributed
        {"technique": "import_access", "effect": "canary_write", "code": "import os\n..."},
    ],
}
```

Invalid configs fail fast with a `ConfigError` naming the offending key.
Timeouts must be positive and finite. `enabled_techniques` filters static
findings only: the prober runs every supplied candidate and every configured
extra payload. To test a subset dynamically, pass that subset as the corpus.

### Logging and reproducibility

* The analyzer and prober modules log through the standard `logging` module
  (`logging.getLogger("sandbox_escape_finder...")`). `DynamicProber` logs one
  `INFO` line per payload (id, technique, executed, escaped, exception,
  duration) and the static analyzer logs each finding at `DEBUG`. Enable with
  `logging.basicConfig(level=logging.INFO)`.
* `seed` controls the **execution order** of the corpus (via `random.Random(seed)`),
  so a given seed reproduces the same order, while elapsed timings can vary;
  each report row records
  its `exec_order`. The returned report is re-sorted into corpus order so the
  table layout is stable regardless of seed.
* `report` rows also carry `executed` — `True` only if the sandbox actually ran
  the payload body. A compile-time `SyntaxError` (RestrictedPython rejecting the
  source) or a `RunnerError` reads as `executed: False`.

## Tests

Run the full suite in the container using `sh scripts/evaluate.sh`. For a local
development run against the known test fixtures after editable installation:

```bash
python -m pytest -q
```

Covers: AST detector positive/negative snippets (including dunder-in-a-string
vs. real attribute access), confidence-threshold and technique filtering, the
oracle against the broken toy sandbox fixture, the timeout fallback path,
payload-type normalization, and the end-to-end corpus run against
RestrictedPython. AST metadata tests cover attributes, calls, both import forms,
JSON serialization, and compatibility with existing `Finding` construction.
The container additionally checks non-root execution, a read-only project,
writable temporary storage, dropped capabilities, `no-new-privileges`, and
loopback-only networking before running pytest.

### Recorded verification

On 2026-10-19, the containerized evaluation passed **69 tests** on Linux ARM64
using Python **3.13.16**, RestrictedPython **8.5**, and pytest **8.4.2**. The
boundary checks passed, including temporary writes and rejection of writes to
the project directory. The unrestricted positive-control test confirmed a
canary write. The quickstart reported **11 static flags, 11 blocked attempts,
0 confirmed escapes, 0 infrastructure errors, and 0 escaped-but-not-flagged
candidates**. The Dockerfile pins the tested Python base image by digest;
the evaluation command prints the built image ID for each run. The macOS
development environment also passed all 69 tests on Python 3.14.3.

Task 6 evaluates real, unmodified RestrictedPython rather than a Hugging Face
model; the general model-specific checklist item does not apply to this task.

## Project layout

```
src/sandbox_escape_finder/
├── __init__.py            # public API
├── _output.py             # shared bounded text buffer
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
* Subprocess execution alone does not contain a Python sandbox escape. Run the
  complete dynamic evaluation inside the supplied restricted container or a
  suitable disposable VM. An escape can still affect writable resources within
  that environment, including other canaries under `/tmp`.
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
  rlimits. These controls bound ordinary misbehavior but do not enforce
  filesystem or network isolation. Docker supplies the outer boundary for the
  documented evaluation command; its resource limits are shared across the
  entire evaluation. A kernel or container-runtime vulnerability remains
  outside this project's threat model.
* The canary oracle assumes a "create-and-leave" effect: a payload that creates
  *then deletes* the canary within one run reads as no-escape (detecting it
  would need in-run filesystem watching).
* `executed` is derived from the child's exception type, so a payload that runs
  and then itself raises a *runtime* `SyntaxError` (e.g. via `compile()`) is
  conservatively labeled `executed=False`.
