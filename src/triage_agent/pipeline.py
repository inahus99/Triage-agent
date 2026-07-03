"""End-to-end wiring: Phase 1 -> Phase 2 -> Phase 3 -> Phase 4.

    raw bytes
      -> static analysis (structured facts + raw strings)
      -> quarantine (raw strings become tagged UNTRUSTED text)
      -> watchdog (scans tagged text for injection attempts)
      -> judgment layer (Gemini; consumes only facts + findings,
                          never raw untrusted text directly)

The `judge` parameter exists so this can be tested end-to-end without
a live Gemini API key -- callers can inject a stub judgment function.
"""

from typing import Callable

from .models import InjectionFinding, StaticFact, TriageVerdict
from .quarantine import quarantine_strings
from .tools.static_analysis import run_static_analysis
from .watchdog import scan_all

JudgeFn = Callable[[list[StaticFact], list[InjectionFinding]], TriageVerdict]


def triage(data: bytes, judge: JudgeFn) -> TriageVerdict:
    """Run the full pipeline over raw sample bytes and produce a verdict.

    `judge` is required explicitly (rather than defaulting to the real
    Gemini call) so every caller has to consciously decide which
    judgment implementation to use -- production code passes
    judgment.render_verdict, tests pass a stub.
    """
    facts, raw_strings = run_static_analysis(data)

    tagged_strings = quarantine_strings(raw_strings)
    findings = scan_all(tagged_strings, source="static_strings")

    return judge(facts, findings)
