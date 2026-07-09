# Triage Agent — Prompt-Injection-Resistant Malware Triage Agent

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design.

## Status

- [x] Phase 1 — Quarantine & tagging layer (`src/triage_agent/quarantine.py`)
- [x] Phase 2 — Structured static-analysis tools (`src/triage_agent/tools/static_analysis.py`)
- [x] Phase 3 — Injection watchdog, rule-based (`src/triage_agent/watchdog.py`)
- [x] Phase 4 — Judgment layer via OpenAI (`src/triage_agent/judgment.py`) — live-tested, correctly resists injection
- [x] Phase 5 — Bounded actions & reporting, SQLite-backed (`src/triage_agent/reporting.py`)
- [x] End-to-end wiring, Phases 1→2→3→4→5 (`src/triage_agent/pipeline.py`) — live-tested with a real injection-laced sample; persistence tested via stub judge
- [ ] Phase 6 — Dynamic/sandbox analysis

## Setup

```bash
python -m venv .venv
.venv/Scripts/activate      # Windows
pip install -r requirements.txt
```

Set `OPENAI_API_KEY` in your environment before using the judgment layer.

## Run tests

```bash
pytest
```

## Run on a real file

```bash
python -m triage_agent.cli path/to/sample.exe
python -m triage_agent.cli path/to/sample.exe --db reports.db   # custom report DB
python -m triage_agent.cli path/to/sample.exe --no-db           # skip persistence
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
  pipeline.py      Wires Phases 1->2->3->4->5 into one triage() call
  cli.py           Command-line entry point: python -m triage_agent.cli <file>
  tools/           Phase 2: static analysis tools (structured output only)
tests/
  test_watchdog.py
  test_static_analysis.py
  test_reporting.py
  test_pipeline.py
  test_cli.py
```
