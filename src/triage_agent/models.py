"""Core data models. The `trust` tag is the enforcement mechanism for the
quarantine principle: anything derived from a sample stays UNTRUSTED forever,
no matter how many tools it passes through.
"""

from enum import Enum
from typing import Literal

from pydantic import BaseModel


class Trust(str, Enum):
    UNTRUSTED = "untrusted"       # raw or derived sample content
    TOOL_DERIVED = "tool_derived" # structured facts produced by a tool
    SYSTEM = "system"             # analyst / fixed instructions only


class TaggedText(BaseModel):
    """A piece of text plus where it came from. Never strip the tag."""
    content: str
    trust: Trust


class StaticFact(BaseModel):
    """Closed, structured output from a static analysis tool.
    No free-text verdict fields on purpose -- see ARCHITECTURE.md.
    """
    tool: str
    fact_type: Literal[
        "hash", "string", "import", "section", "pe_header", "network",
        "behavior_score", "suspicious_api", "indicator",
    ]
    key: str
    value: str
    trust: Trust = Trust.TOOL_DERIVED


class InjectionFinding(BaseModel):
    source: str          # which tool/field the suspicious text came from
    pattern: str          # which detector rule matched
    excerpt: str          # the tagged, untrusted excerpt itself
    trust: Trust = Trust.UNTRUSTED


class TriageVerdict(BaseModel):
    severity: Literal["benign", "suspicious", "malicious"]
    confidence: float
    reasoning_summary: str
    injection_findings: list[InjectionFinding] = []
    needs_human_review: bool = False
