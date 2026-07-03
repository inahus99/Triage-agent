"""Phase 3: Injection Watchdog.

Rule-based first pass over untrusted text. Doesn't block analysis -- flags
matches as findings, which become part of the report (see ARCHITECTURE.md,
"Continue-on-detection").
"""

import re
import unicodedata

from .models import InjectionFinding, TaggedText

# Phrases that mimic instructions/system messages rather than sample data.
_INSTRUCTION_PATTERNS: list[tuple[str, str]] = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", "instruction_override"),
    (r"\byou\s+are\s+now\b", "role_override"),
    (r"\[?system\]?\s*:", "fake_system_message"),
    (r"\bverdict\s*:\s*(benign|safe|clean)\b", "fake_verdict_injection"),
    (r"disregard\s+(the\s+)?(analyst|user)", "authority_override"),
    (r"do\s+not\s+(flag|report|scan|analyze)", "suppression_attempt"),
    (r"new\s+instructions?\s*:", "instruction_override"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), name) for p, name in _INSTRUCTION_PATTERNS]


def _normalize_confusables(text: str) -> str:
    """Collapse unicode lookalikes (e.g. Cyrillic 'а') and zero-width chars
    so obfuscated injection attempts still match the plain-ASCII patterns."""
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    zero_width = ["​", "‌", "‍", "﻿"]
    for zw in zero_width:
        text = text.replace(zw, "")
    return text


def scan(tagged: TaggedText, source: str) -> list[InjectionFinding]:
    """Scan a single tagged, untrusted string for injection attempts."""
    findings: list[InjectionFinding] = []
    normalized = _normalize_confusables(tagged.content)

    for pattern, name in _COMPILED:
        match = pattern.search(normalized)
        if match:
            start = max(match.start() - 20, 0)
            end = min(match.end() + 20, len(normalized))
            findings.append(
                InjectionFinding(
                    source=source,
                    pattern=name,
                    excerpt=normalized[start:end],
                )
            )
    return findings


def scan_all(tagged_items: list[TaggedText], source: str) -> list[InjectionFinding]:
    findings: list[InjectionFinding] = []
    for item in tagged_items:
        findings.extend(scan(item, source))
    return findings
