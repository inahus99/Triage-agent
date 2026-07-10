"""VirusTotal hash-lookup enrichment (read-only, free tier).

Looks a sample's SHA-256 up in VirusTotal's existing corpus -- no file
submission, so it works on the free API tier and never sends the sample
anywhere. Returns closed StaticFacts only (detection counts, reputation),
never free text, so it slots in alongside static analysis without opening
a tool-output-poisoning route.

Requires VIRUSTOTAL_API_KEY in the environment.
"""

import os

import requests

from ..models import StaticFact

_BASE_URL = "https://www.virustotal.com/api/v3/files"


def _headers() -> dict:
    return {"x-apikey": os.environ["VIRUSTOTAL_API_KEY"]}


def lookup_hash(sha256: str) -> list[StaticFact]:
    """Look up an existing VT report by hash. Returns [] if the hash is
    unknown to VT (a 404 is normal, not an error) so triage continues."""
    response = requests.get(f"{_BASE_URL}/{sha256}", headers=_headers(), timeout=30)
    if response.status_code == 404:
        return [StaticFact(tool="virustotal", fact_type="behavior_score", key="vt_known", value="false")]
    response.raise_for_status()
    return parse_vt_response(response.json())


def parse_vt_response(payload: dict) -> list[StaticFact]:
    """Extract closed reputation facts from a VT /files response."""
    attributes = payload.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {}) or {}

    facts = [StaticFact(tool="virustotal", fact_type="behavior_score", key="vt_known", value="true")]
    for key in ("malicious", "suspicious", "harmless", "undetected"):
        if key in stats:
            facts.append(
                StaticFact(tool="virustotal", fact_type="behavior_score",
                           key=f"vt_{key}", value=str(stats[key]))
            )
    if "reputation" in attributes:
        facts.append(
            StaticFact(tool="virustotal", fact_type="behavior_score",
                       key="vt_reputation", value=str(attributes["reputation"]))
        )
    return facts
