"""Phase 2: Structured static-analysis tools.

Every function here returns StaticFact objects (closed fields only) or
raw strings destined for quarantine -- never a free-text verdict. This
is what closes the tool-output-poisoning route: there is no sentence
field for an attacker to hijack.
"""

import hashlib
import re

import pefile

from ..models import StaticFact
from .indicators import extract_indicators

_MIN_STRING_LEN = 4
_ASCII_STRING_RE = re.compile(rb"[\x20-\x7e]{%d,}" % _MIN_STRING_LEN)
# Runs of printable characters after UTF-8 decoding: excludes C0/C1 control
# chars but keeps non-ASCII letters, so homoglyph-obfuscated text survives as
# a contiguous string instead of being split apart by the ASCII extractor.
_UNICODE_STRING_RE = re.compile(r"[^\x00-\x1f\x7f-\x9f]{%d,}" % _MIN_STRING_LEN)


def extract_ascii_strings(data: bytes) -> list[str]:
    """Pull printable ASCII strings out of raw sample bytes.

    Output is raw and MUST be quarantined (see quarantine.py) before
    it is used anywhere else -- it is attacker-controlled content.
    """
    return [m.group().decode("ascii") for m in _ASCII_STRING_RE.finditer(data)]


def extract_unicode_strings(data: bytes) -> list[str]:
    """Pull printable strings out after decoding as UTF-8.

    Complements extract_ascii_strings: the ASCII extractor operates on raw
    bytes and splits a string apart on any non-ASCII byte, so text using
    Unicode homoglyphs (e.g. Cyrillic lookalikes) never reaches the watchdog
    as a whole phrase. Decoding first keeps such phrases intact.
    """
    text = data.decode("utf-8", errors="ignore")
    return [m.group() for m in _UNICODE_STRING_RE.finditer(text)]


def compute_hashes(data: bytes) -> list[StaticFact]:
    return [
        StaticFact(tool="hashlib", fact_type="hash", key="md5", value=hashlib.md5(data).hexdigest()),
        StaticFact(tool="hashlib", fact_type="hash", key="sha1", value=hashlib.sha1(data).hexdigest()),
        StaticFact(tool="hashlib", fact_type="hash", key="sha256", value=hashlib.sha256(data).hexdigest()),
    ]


def parse_pe_facts(data: bytes) -> list[StaticFact]:
    """Parse PE header, imports, and sections into structured facts.

    Returns an empty list (not an error) for non-PE input -- a sample
    not being a PE file is itself just a fact, not a failure.
    """
    facts: list[StaticFact] = []
    try:
        pe = pefile.PE(data=data)
    except pefile.PEFormatError:
        return facts

    facts.append(
        StaticFact(
            tool="pefile",
            fact_type="pe_header",
            key="machine",
            value=hex(pe.FILE_HEADER.Machine),
        )
    )
    facts.append(
        StaticFact(
            tool="pefile",
            fact_type="pe_header",
            key="timestamp",
            value=str(pe.FILE_HEADER.TimeDateStamp),
        )
    )

    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        facts.append(
            StaticFact(tool="pefile", fact_type="section", key=name, value=str(section.SizeOfRawData))
        )

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("ascii", errors="replace") if entry.dll else "unknown"
            for imp in entry.imports:
                if imp.name:
                    facts.append(
                        StaticFact(
                            tool="pefile",
                            fact_type="import",
                            key=dll,
                            value=imp.name.decode("ascii", errors="replace"),
                        )
                    )

    pe.close()
    return facts


def run_static_analysis(data: bytes) -> tuple[list[StaticFact], list[str]]:
    """Full Phase 2 pass over raw sample bytes.

    Returns (structured_facts, raw_strings). raw_strings is NOT yet
    quarantined -- the caller is responsible for passing it through
    quarantine.py before it reaches the watchdog or judgment layer.
    """
    facts = compute_hashes(data) + parse_pe_facts(data)
    # Combine ASCII and UTF-8 string extraction, de-duplicated while preserving
    # order, so both plain-ASCII and Unicode-homoglyph text reach the watchdog.
    raw_strings = list(dict.fromkeys(extract_ascii_strings(data) + extract_unicode_strings(data)))
    # Surface malware indicators from those strings as structured facts so the
    # judge can see them without ever receiving the raw strings themselves.
    facts += extract_indicators(raw_strings)
    return facts, raw_strings
