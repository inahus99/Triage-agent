# Triage Agent — Prompt-Injection-Resistant Malware Triage Agent

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design.

## Status

- [x] Phase 1 — Quarantine & tagging layer (`src/triage_agent/quarantine.py`)
- [x] Phase 2 — Structured static-analysis tools (`src/triage_agent/tools/static_analysis.py`)
- [x] Phase 3 — Injection watchdog, rule-based (`src/triage_agent/watchdog.py`) — handles plain text, zero-width chars, Unicode homoglyphs, and base64-encoded payloads
- [x] Phase 4 — Judgment layer via OpenAI (`src/triage_agent/judgment.py`) — live-tested, correctly resists injection
- [x] Phase 5 — Bounded actions & reporting, SQLite-backed (`src/triage_agent/reporting.py`)
- [x] End-to-end wiring, Phases 1→2→3→4→5 (`src/triage_agent/pipeline.py`) — live-tested with a real injection-laced sample; persistence tested via stub judge
- [~] Phase 6 — Dynamic/sandbox analysis via Hybrid Analysis (`src/triage_agent/tools/dynamic_analysis.py`) — **blocked**: code is built and unit-tested (HTTP-mocked), but live submission requires a Hybrid Analysis account with `default`-level API access; free/community keys are `restricted` and get a 404 on `/submit/file`. See "Phase 6 status" below.

**Project considered feature-complete at Phases 1–5 + CLI.** Phase 6 is optional and can be unblocked later without changing any other phase.

## Phase 6 status (blocked)

Verified live against a real Hybrid Analysis community API key:
- `GET /key/current` succeeds and reports `auth_level_name: "restricted"`
- `POST /submit/file` returns `404 {"message": "Requested URI - Not Found"}` for this account tier
- Read-only endpoints (e.g. `/search/hash`) are reachable, confirming it's a privilege gate, not a code or routing bug

To unblock: request elevated (`default`) API access from Hybrid Analysis, or swap `tools/dynamic_analysis.py` for a provider that allows free submission (e.g. any.run's community tier). No other phase depends on this — `pipeline.triage()`'s `dynamic_analysis` parameter is optional and the CLI's `--dynamic` flag simply errors clearly if unset/unavailable.

## Setup

```bash
python -m venv .venv
.venv/Scripts/activate      # Windows
pip install -r requirements.txt
```

Set `OPENAI_API_KEY` in your environment before using the judgment layer.
Set `HYBRID_ANALYSIS_API_KEY` (free at hybrid-analysis.com) before using `--dynamic`.

## Run tests

```bash
pytest
```

## Evaluate the watchdog

Scores the injection watchdog against a labeled corpus (detection rate +
false-positive rate). No API calls, runs in a fraction of a second:

```bash
python -m triage_agent.evaluation
```

## Run on a real file

```bash
python -m triage_agent.cli path/to/sample.exe
python -m triage_agent.cli path/to/sample.exe --db reports.db   # custom report DB
python -m triage_agent.cli path/to/sample.exe --no-db           # skip persistence
python -m triage_agent.cli path/to/sample.exe --dynamic         # also detonate in a cloud sandbox
```

Reads `OPENAI_API_KEY` from a `.env` file in the current directory (see
`.env.example`) if it isn't already set in the environment.

## Layout

```
src/triage_agent/
  models.py       Trust-tagged data models (TaggedText, StaticFact, TriageVerdict)
  quarantine.py    Phase 1: wraps raw sample data as untrusted
  watchdog.py      Phase 3: rule-based injection detector
  judgment.py      Phase 4: OpenAI-backed verdict layer
  reporting.py     Phase 5: bounded actions (save_report, escalate) + SQLite storage
  pipeline.py      Wires Phases 1->2->3->4->5, optional Phase 6, into one triage() call
  cli.py           Command-line entry point: python -m triage_agent.cli <file>
  tools/           Phase 2 static analysis + Phase 6 dynamic/sandbox analysis (structured output only)
tests/
  test_watchdog.py
  test_static_analysis.py
  test_dynamic_analysis.py
  test_reporting.py
  test_pipeline.py
  test_cli.py
```
