"""Phase 6: Dynamic/sandbox analysis via Hybrid Analysis (Falcon Sandbox).

Submits a sample to a cloud sandbox for detonation and converts the
resulting behavior report into facts, split the same way Phase 2
splits static analysis:

  - vendor-computed numbers/enums (threat score, verdict) are safe,
    closed StaticFacts -- the vendor computed them, not the malware.
  - domains/hosts/classification tags are text an attacker can
    influence (e.g. a C2 domain crafted to look like an instruction),
    so they're returned as raw strings for the caller to quarantine
    and watchdog-scan exactly like static strings.

Detonation happens on Hybrid Analysis's infrastructure, never locally.
Requires HYBRID_ANALYSIS_API_KEY in the environment.
"""

import os
import time

import requests

from ..models import StaticFact

_BASE_URL = "https://www.hybrid-analysis.com/api/v2"
_DEFAULT_ENVIRONMENT_ID = 160  # Windows 10 64-bit


class SandboxError(RuntimeError):
    pass


def _headers() -> dict:
    api_key = os.environ["HYBRID_ANALYSIS_API_KEY"]
    return {"api-key": api_key, "user-agent": "Falcon Sandbox"}


def submit_file(data: bytes, filename: str, environment_id: int = _DEFAULT_ENVIRONMENT_ID) -> str:
    """Submit a file for detonation. Returns a job_id to poll."""
    response = requests.post(
        f"{_BASE_URL}/submit/file",
        headers=_headers(),
        files={"file": (filename, data)},
        data={"environment_id": environment_id},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["job_id"]


def wait_for_report(job_id: str, poll_interval: float = 10.0, timeout: float = 600.0) -> dict:
    """Poll until the sandbox job completes, return the raw summary report."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = requests.get(f"{_BASE_URL}/report/{job_id}/summary", headers=_headers(), timeout=30)
        if response.status_code == 200:
            report = response.json()
            if report.get("state") in ("SUCCESS", "ERROR"):
                return report
        time.sleep(poll_interval)
    raise SandboxError(f"sandbox report for job {job_id} did not complete within {timeout}s")


def parse_report(report: dict) -> tuple[list[StaticFact], list[str]]:
    """Split a sandbox summary report into (structured_facts, raw_strings).

    Mirrors static_analysis.run_static_analysis's return shape so the
    caller can quarantine + watchdog-scan raw_strings identically.
    """
    facts: list[StaticFact] = []
    raw_strings: list[str] = []

    threat_score = report.get("threat_score")
    if threat_score is not None:
        facts.append(
            StaticFact(tool="hybrid_analysis", fact_type="behavior_score", key="threat_score", value=str(threat_score))
        )

    verdict = report.get("verdict")
    if verdict is not None:
        facts.append(
            StaticFact(tool="hybrid_analysis", fact_type="behavior_score", key="sandbox_verdict", value=str(verdict))
        )

    for domain in report.get("domains", []) or []:
        raw_strings.append(str(domain))
    for host in report.get("hosts", []) or []:
        raw_strings.append(str(host))
    for tag in report.get("classification_tags", []) or []:
        raw_strings.append(str(tag))

    return facts, raw_strings


def run_dynamic_analysis(data: bytes, filename: str = "sample.bin") -> tuple[list[StaticFact], list[str]]:
    """Full Phase 6 pass: submit, wait, parse into (facts, raw_strings)."""
    job_id = submit_file(data, filename)
    report = wait_for_report(job_id)
    return parse_report(report)
