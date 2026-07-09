"""End-to-end wiring: Phase 1 -> Phase 2 -> Phase 3 -> Phase 4 -> Phase 5.

    raw bytes
      -> static analysis (structured facts + raw strings)
      -> quarantine (raw strings become tagged UNTRUSTED text)
      -> watchdog (scans tagged text for injection attempts)
      -> judgment layer (consumes only facts + findings,
                          never raw untrusted text directly)
      -> reporting (persist verdict; auto-escalate if flagged)

The `judge` parameter exists so this can be tested end-to-end without
a live LLM API key -- callers can inject a stub judgment function.
`conn` is optional: pass a reporting.init_db() connection to persist
the verdict via the bounded action set in reporting.py.
"""

import sqlite3
from typing import Callable

from .models import InjectionFinding, StaticFact, TriageVerdict
from .quarantine import quarantine_strings
from .reporting import escalate, save_report
from .tools.static_analysis import compute_hashes, run_static_analysis
from .watchdog import scan_all

JudgeFn = Callable[[list[StaticFact], list[InjectionFinding]], TriageVerdict]


def triage(
    data: bytes,
    judge: JudgeFn,
    conn: sqlite3.Connection | None = None,
) -> TriageVerdict:
    """Run the full pipeline over raw sample bytes and produce a verdict.

    `judge` is required explicitly (rather than defaulting to the real
    OpenAI call) so every caller has to consciously decide which
    judgment implementation to use -- production code passes
    judgment.render_verdict, tests pass a stub.
    """
    facts, raw_strings = run_static_analysis(data)

    tagged_strings = quarantine_strings(raw_strings)
    findings = scan_all(tagged_strings, source="static_strings")

    verdict = judge(facts, findings)

    if conn is not None:
        sha256 = next(f.value for f in compute_hashes(data) if f.key == "sha256")
        report_id = save_report(conn, sha256, verdict)
        if verdict.needs_human_review:
            escalate(conn, report_id)

    return verdict
