"""Phase 1: Quarantine & Tagging Layer.

Every raw byte/string pulled from a sample enters here first and gets
wrapped as UNTRUSTED before anything else touches it.
"""

from .models import TaggedText, Trust


def quarantine_strings(raw_strings: list[str]) -> list[TaggedText]:
    """Wrap raw strings extracted from a sample as untrusted evidence."""
    return [TaggedText(content=s, trust=Trust.UNTRUSTED) for s in raw_strings]


def quarantine_bytes_as_text(raw: bytes, encoding: str = "latin-1") -> TaggedText:
    return TaggedText(content=raw.decode(encoding, errors="replace"), trust=Trust.UNTRUSTED)
