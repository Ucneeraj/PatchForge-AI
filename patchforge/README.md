# PatchForge-AI — Multi-Agent Framework

**Milestone 2 status: complete**, plus a working real-fix pipeline beyond
it: give it a GitHub link (or local path), it clones the repo, makes a
disposable corrected copy, applies REAL automatic fixes for supported
vulnerability classes to that copy, runs REAL validation (the repo's own
tests if it has them, else a syntax check), and reports what changed —
without ever touching the original repo. No Docker or LLM API key
required for this to work today; both are pluggable for later.

## Structure

```
patchforge_project/
├── pytest.ini
├── requirements.txt
├── README.md
├── tests/                          # 33 tests, all passing
└── patchforge/                     # the package
    ├── protocol.py                 # typed messages agents pass between each other
    ├── orchestrator.py             # state machine: scan -> plan -> patch -> test -> reflect
    ├── main.py                     # interactive prompt, or `main.py <github-url-or-path>`, or `main.py --demo`
    └── agents/
        ├── base_agent.py           # shared logging/timing wrapper
        ├── repo_ingestion_agent.py # clones a repo / walks a local path, language-scoped file discovery
        ├── scanner_agent.py        # AST-based CWE detection (real, not a stub)
        ├── planner_agent.py        # prioritizes findings, picks a strategy
        ├── patch_generator_agent.py# REAL rule-based auto-fix (regex-derived from actual code) + pluggable LLM interface
        ├── sandbox_runner_agent.py # 3 backends: Docker (production), Local (real, no Docker), Mock (demo)
        ├── verifier_agent.py       # Reflexion-style failure diagnosis + retry/escalate
        └── report_agent.py         # turns a RepoScanReport into a readable markdown summary
```

## Run it — interactive

```bash
cd patchforge_project
python3 -m patchforge.main
```

Prompts you for a GitHub link or local path. Press Enter with nothing
typed to run the built-in single-file demo instead.

## Run it — direct

```bash
python3 -m patchforge.main https://github.com/some-user/some-repo
python3 -m patchforge.main /path/to/local/repo   # no network needed
python3 -m patchforge.main --demo                # single-file demo, no prompt
```

## Run the web dashboard

```bash
pip install -r requirements.txt
streamlit run app.py
```

Opens at `http://localhost:8501`. Paste a GitHub link or local path and
click "Run Scan". **Test it first against `sample_vulnerable.py`**
(included in this project root) to confirm the pipeline itself works —
it's guaranteed to trigger both currently-supported rules. If a
real-world repo shows zero findings, that can legitimately mean either
the code has none of the two currently-detected vulnerability patterns,
or it uses a variant our rules don't match yet (e.g. string
concatenation instead of f-strings) — not necessarily a bug.

**What repo mode actually does, for real:**
1. Clones (or opens) the repo.
2. Copies it to `<repo>_corrected` — the original is never modified.
3. Scans every **Python** file (other languages are detected and
   honestly reported as "not scanned yet", never silently skipped).
4. For each finding, derives a real fix by pattern-matching the ACTUAL
   flagged code (not a canned example) — currently supports SQL
   injection via string interpolation (CWE-89) and hardcoded secrets
   (CWE-798).
5. Applies the fix to the corrected copy, then validates for real: runs
   the repo's own tests if it has any, otherwise does a Python syntax
   check — labeled honestly either way, never reported as a test pass
   when it was only a syntax check.
6. Retries (informed by why the previous attempt failed) up to the
   iteration cap, or escalates for human review if it can't resolve it.
7. Prints a markdown report and tells you where the corrected copy lives.

Tested against a genuinely unseen sample repo (different variable names,
both f-string and %-formatted SQL injection, a differently-named secret)
and it fixed all three correctly on the first try — see the corrected
file's diff for proof this isn't hardcoded to the demo example.

**Known limitation:** if a fix needs a new import (e.g. `os.environ` for
the secret fix) and the file doesn't already import `os`, it isn't added
automatically yet — worth knowing before a live demo.

## Run the tests

```bash
pip install -r requirements.txt
pytest -v
```

33 tests: scanner (true/false positives per CWE rule), planner
(prioritization + strategy selection), patch generator (real auto-fix
correctness AND honest fallback when it can't fix something), verifier
(retry vs. escalate logic), single-file orchestration, and repo
ingestion/repair (multi-file discovery, ignored directories, language
scoping, full `run_repo` pass) — all offline and deterministic.

## What's real vs. what's still a stub

- **Real:** AST-based scanning, the typed protocol, orchestration state
  machine, Reflector retry/escalate logic, rule-based auto-fix for CWE-89
  and CWE-798 (works on arbitrary matching code), the local sandbox
  (real file edits + real test/syntax validation on a disposable copy).
- **Stubbed (pluggable, swap in when ready):**
  - Any vulnerability class beyond the two rule-based fixes needs either
    a wider rule set or a real LLM client behind `PatchLLMClient` in
    `patch_generator_agent.py`.
  - `DockerSandboxBackend` in `sandbox_runner_agent.py` is sketched but
    not wired as the default — `LocalSandboxBackend` is what actually
    runs today, using a copied directory instead of a container.
  - Multi-language support (JS/TS/etc.) — see `repo_ingestion_agent.py`
    for exactly what adding one requires.

## Design notes

- Agents never pass prose to each other — only the dataclasses in
  `protocol.py`.
- The rule-based fixer is honest about its limits: when it can't
  confidently derive a fix, it returns `replacement_code=None` rather
  than fabricating one, and the sandbox correctly reports that as a
  failure instead of a false success.
- `Orchestrator.max_iterations` and the sandbox's `timeout_seconds` are
  where cost-boundedness and time-boxing are enforced concretely.
