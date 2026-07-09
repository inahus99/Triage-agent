"""Phase 5: Bounded actions & reporting.

This is the only place a TriageVerdict is allowed to turn into a
persisted, real-world effect. The judgment layer (Phase 4) cannot
write to the database, escalate, or take any action directly -- it
only returns a TriageVerdict, and this module is the fixed, small menu
of things that can be done with one:

  - save_report   : persist the verdict
  - escalate      : mark a report as needing analyst attention

There is no "run arbitrary command" action. Even a fully successful
prompt injection that fooled the judgment layer into returning a
crafted verdict still can't reach beyond these two effects.
"""

import json
import sqlite3
from pathlib import Path

from .models import TriageVerdict

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_sha256 TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    reasoning_summary TEXT NOT NULL,
    injection_findings_json TEXT NOT NULL,
    needs_human_review INTEGER NOT NULL,
    escalated INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def init_db(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute(_SCHEMA)
    conn.commit()
    return conn


def save_report(conn: sqlite3.Connection, sample_sha256: str, verdict: TriageVerdict) -> int:
    """The only allowed action for writing a verdict to storage."""
    cursor = conn.execute(
        """
        INSERT INTO reports
            (sample_sha256, severity, confidence, reasoning_summary,
             injection_findings_json, needs_human_review)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            sample_sha256,
            verdict.severity,
            verdict.confidence,
            verdict.reasoning_summary,
            json.dumps([f.model_dump(mode="json") for f in verdict.injection_findings]),
            int(verdict.needs_human_review),
        ),
    )
    conn.commit()
    return cursor.lastrowid


def escalate(conn: sqlite3.Connection, report_id: int) -> None:
    """The only allowed action for flagging a report for human review."""
    conn.execute("UPDATE reports SET escalated = 1 WHERE id = ?", (report_id,))
    conn.commit()


def get_pending_review(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    return conn.execute(
        "SELECT * FROM reports WHERE needs_human_review = 1 AND escalated = 0"
    ).fetchall()
