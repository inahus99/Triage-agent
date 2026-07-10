from triage_agent.models import InjectionFinding, TriageVerdict
from triage_agent.pipeline import reconcile_layers


def _finding():
    return InjectionFinding(source="s", pattern="instruction_override", excerpt="ignore all previous")


def test_disagreement_forces_human_review():
    # watchdog flagged injection, but judge said benign -> escalate
    verdict = TriageVerdict(severity="benign", confidence=0.9, reasoning_summary="looks fine",
                            needs_human_review=False)
    out = reconcile_layers(verdict, [_finding()])
    assert out.needs_human_review is True
    assert "layer-disagreement" in out.reasoning_summary


def test_agreement_malicious_is_left_unchanged():
    verdict = TriageVerdict(severity="malicious", confidence=0.9, reasoning_summary="bad",
                            needs_human_review=True)
    out = reconcile_layers(verdict, [_finding()])
    assert out.reasoning_summary == "bad"  # untouched


def test_no_findings_leaves_benign_verdict_untouched():
    verdict = TriageVerdict(severity="benign", confidence=0.9, reasoning_summary="clean",
                            needs_human_review=False)
    out = reconcile_layers(verdict, [])
    assert out.needs_human_review is False
    assert out.reasoning_summary == "clean"


def test_suspicious_with_findings_still_escalates():
    verdict = TriageVerdict(severity="suspicious", confidence=0.5, reasoning_summary="hmm",
                            needs_human_review=False)
    out = reconcile_layers(verdict, [_finding()])
    assert out.needs_human_review is True
