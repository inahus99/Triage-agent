import hashlib
import struct

from triage_agent.tools.static_analysis import (
    compute_hashes,
    extract_ascii_strings,
    parse_pe_facts,
    run_static_analysis,
)


def test_extract_ascii_strings_finds_readable_text():
    data = b"\x00\x01\x02" + b"kernel32.dll" + b"\x00\x00" + b"GetProcAddress" + b"\xff\xfe"
    strings = extract_ascii_strings(data)
    assert "kernel32.dll" in strings
    assert "GetProcAddress" in strings


def test_extract_ascii_strings_ignores_short_fragments():
    data = b"\x00ab\x00cd\x00"
    strings = extract_ascii_strings(data)
    assert strings == []


def test_compute_hashes_matches_hashlib():
    data = b"sample content for hashing"
    facts = compute_hashes(data)
    values = {f.key: f.value for f in facts}
    assert values["md5"] == hashlib.md5(data).hexdigest()
    assert values["sha1"] == hashlib.sha1(data).hexdigest()
    assert values["sha256"] == hashlib.sha256(data).hexdigest()


def test_compute_hashes_all_tagged_tool_derived():
    facts = compute_hashes(b"x")
    assert all(f.trust == "tool_derived" for f in facts)


def test_parse_pe_facts_returns_empty_for_non_pe_data():
    assert parse_pe_facts(b"not a pe file at all") == []


def _build_minimal_pe() -> bytes:
    """Smallest byte sequence pefile will accept as a PE: valid DOS
    header pointing to a valid PE header with FILE_HEADER + minimal
    OPTIONAL_HEADER, no sections."""
    dos_stub = bytearray(64)
    dos_stub[0:2] = b"MZ"
    pe_offset = 64
    struct.pack_into("<I", dos_stub, 0x3C, pe_offset)

    pe_sig = b"PE\x00\x00"
    file_header = struct.pack(
        "<HHIIIHH",
        0x014C,  # Machine: I386
        0,       # NumberOfSections
        0,       # TimeDateStamp
        0, 0,    # PointerToSymbolTable, NumberOfSymbols
        0xE0,    # SizeOfOptionalHeader
        0x0102,  # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
    )
    optional_header = bytearray(0xE0)
    struct.pack_into("<H", optional_header, 0, 0x010B)  # Magic: PE32

    return bytes(dos_stub) + pe_sig + file_header + bytes(optional_header)


def test_parse_pe_facts_extracts_machine_type_from_valid_pe():
    facts = parse_pe_facts(_build_minimal_pe())
    machine_facts = [f for f in facts if f.key == "machine"]
    assert len(machine_facts) == 1
    assert machine_facts[0].value == "0x14c"


def test_run_static_analysis_separates_facts_from_raw_strings():
    data = b"\x00\x00" + b"suspicious.dll" + b"\x00\x00"
    facts, raw_strings = run_static_analysis(data)
    assert any(f.fact_type == "hash" for f in facts)
    assert "suspicious.dll" in raw_strings
    # raw_strings must be plain str, not yet wrapped/tagged -- that's quarantine's job
    assert all(isinstance(s, str) for s in raw_strings)
