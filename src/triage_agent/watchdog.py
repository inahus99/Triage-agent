"""Phase 3: Injection Watchdog.

Rule-based first pass over untrusted text. Doesn't block analysis -- flags
matches as findings, which become part of the report (see ARCHITECTURE.md,
"Continue-on-detection").

Handles three obfuscation routes on top of plain text:
  - zero-width characters inserted mid-word
  - Unicode homoglyphs (Cyrillic/Greek lookalikes for Latin letters)
  - base64-encoded payloads (decoded and re-scanned)
"""

import base64
import binascii
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

_ZERO_WIDTH = ["​", "‌", "‍", "﻿"]

# Common Cyrillic/Greek characters that visually mimic Latin letters. NFKD
# normalization does NOT collapse these (they are distinct letters, not
# compatibility variants), so they need an explicit mapping.
_CONFUSABLES = {
    # Cyrillic lowercase
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ѕ": "s", "ј": "j", "ԛ": "q", "ԝ": "w", "ѵ": "v", "н": "h",
    "м": "m", "т": "t", "к": "k", "в": "b",
    # Cyrillic uppercase
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I", "Ѕ": "S", "Ј": "J",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "ε": "e", "ν": "v", "ι": "i", "κ": "k",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "Ζ": "Z",
}
_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLES)

# Runs of base64 alphabet long enough to plausibly hide a phrase.
_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _normalize_confusables(text: str) -> str:
    """Collapse unicode lookalikes and zero-width chars so obfuscated
    injection attempts still match the plain-ASCII patterns."""
    for zw in _ZERO_WIDTH:
        text = text.replace(zw, "")
    text = text.translate(_CONFUSABLE_TABLE)
    # NFKD still handles accented/compatibility forms the table doesn't cover.
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    return text


def _decode_base64_payloads(text: str) -> list[str]:
    """Find base64-looking runs, decode any that yield printable UTF-8 text."""
    decoded: list[str] = []
    for match in _B64_RE.finditer(text):
        token = match.group()
        padded = token + "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
            candidate = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if not candidate:
            continue
        printable = sum(1 for c in candidate if c.isprintable() or c.isspace())
        if printable / len(candidate) > 0.8:
            decoded.append(candidate)
    return decoded


def _match_patterns(text: str, source: str, note: str = "") -> list[InjectionFinding]:
    findings: list[InjectionFinding] = []
    for pattern, name in _COMPILED:
        match = pattern.search(text)
        if match:
            start = max(match.start() - 20, 0)
            end = min(match.end() + 20, len(text))
            findings.append(
                InjectionFinding(source=source, pattern=name, excerpt=note + text[start:end])
            )
    return findings


def scan(tagged: TaggedText, source: str) -> list[InjectionFinding]:
    """Scan a single tagged, untrusted string for injection attempts."""
    normalized = _normalize_confusables(tagged.content)
    findings = _match_patterns(normalized, source)

    # Re-scan anything hidden inside a base64 blob.
    for decoded in _decode_base64_payloads(tagged.content):
        decoded_normalized = _normalize_confusables(decoded)
        findings.extend(_match_patterns(decoded_normalized, source, note="[base64-decoded] "))

    return findings


def scan_all(tagged_items: list[TaggedText], source: str) -> list[InjectionFinding]:
    findings: list[InjectionFinding] = []
    for item in tagged_items:
        findings.extend(scan(item, source))
    return findings
