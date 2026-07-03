# Triage Agent — Prompt-Injection-Resistant Malware Triage Agent

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design.

## Status

- [x] Phase 1 — Quarantine & tagging layer (`src/triage_agent/quarantine.py`)
- [x] Phase 2 — Structured static-analysis tools (`src/triage_agent/tools/static_analysis.py`)
- [x] Phase 3 — Injection watchdog, rule-based (`src/triage_agent/watchdog.py`)
- [~] Phase 4 — Judgment layer via Gemini (`src/triage_agent/judgment.py`) — implemented, untested end-to-end
- [ ] Phase 5 — Bounded actions & reporting
- [ ] Phase 6 — Dynamic/sandbox analysis

## Setup

```bash
python -m venv .venv
.venv/Scripts/activate      # Windows
pip install -r requirements.txt
```

Set `GEMINI_API_KEY` in your environment before using the judgment layer.

## Run tests

```bash
pytest
```

## Layout

```
src/triage_agent/
  models.py       Trust-tagged data models (TaggedText, StaticFact, TriageVerdict)
  quarantine.py    Phase 1: wraps raw sample data as untrusted
  watchdog.py      Phase 3: rule-based injection detector
  judgment.py      Phase 4: Gemini-backed verdict layer
  tools/           Phase 2: static analysis tools (structured output only)
tests/
  test_watchdog.py
```
