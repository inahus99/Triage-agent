from triage_agent.models import InjectionFinding, TriageVerdict
from triage_agent.reporting import escalate, get_pending_review, init_db, save_report


def _memory_db():
    return init_db(":memory:")


def test_save_report_persists_verdict_fields():
    conn = _memory_db()
    verdict = TriageVerdict(
        severity="malicious",
        confidence=0.9,
        reasoning_summary="test reasoning",
        injection_findings=[],
        needs_human_review=False,
    )
    report_id = save_report(conn, "deadbeef" * 8, verdict)

    row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    assert row is not None
    assert row[1] == "deadbeef" * 8  # sample_sha256
    assert row[2] == "malicious"     # severity


def test_pending_review_excludes_reports_not_needing_review():
    conn = _memory_db()
    clean = TriageVerdict(severity="benign", confidence=0.9, reasoning_summary="ok", needs_human_review=False)
    flagged = TriageVerdict(severity="malicious", confidence=0.5, reasoning_summary="sus", needs_human_review=True)

    save_report(conn, "aaa", clean)
    save_report(conn, "bbb", flagged)

    pending = get_pending_review(conn)
    assert len(pending) == 1
    assert pending[0]["sample_sha256"] == "bbb"


def test_escalate_removes_report_from_pending_review():
    conn = _memory_db()
    flagged = TriageVerdict(severity="malicious", confidence=0.5, reasoning_summary="sus", needs_human_review=True)
    report_id = save_report(conn, "bbb", flagged)

    assert len(get_pending_review(conn)) == 1
    escalate(conn, report_id)
    assert len(get_pending_review(conn)) == 0


def test_injection_findings_are_persisted_as_json():
    conn = _memory_db()
    finding = InjectionFinding(source="strings", pattern="instruction_override", excerpt="ignore all previous")
    verdict = TriageVerdict(
        severity="malicious", confidence=0.9, reasoning_summary="bad",
        injection_findings=[finding], needs_human_review=True,
    )
    report_id = save_report(conn, "ccc", verdict)

    row = conn.execute(
        "SELECT injection_findings_json FROM reports WHERE id = ?", (report_id,)
    ).fetchone()
    assert "instruction_override" in row[0]
