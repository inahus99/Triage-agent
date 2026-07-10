"""Malware indicator extractor.

Turns suspicious strings into STRUCTURED facts so the judgment layer can
reason about maliciousness without ever receiving raw sample text. This
closes the gap where the injection defense (raw strings never reach the
LLM) also starved the LLM of ordinary malware evidence.

Safety: fact values come from OUR fixed vocabulary (the matched indicator
token / category), never a free-text span copied from the sample, so an
indicator fact cannot carry a smuggled instruction. Network URLs are the
one attacker-controlled value -- capped in length and already
watchdog-scanned upstream -- and contain no whitespace, so they cannot
carry a multi-word instruction.
"""

import re

from ..models import StaticFact

# Windows API names grouped by the malicious capability they signal.
# Matching a name means the SAMPLE referenced it; the fact value is the
# capability label (our vocabulary), so nothing attacker-authored leaks.
_API_INDICATORS: dict[str, list[str]] = {
    "process_injection": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                          "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext"],
    "keylogging": ["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyboardState", "MapVirtualKey"],
    "crypto_ransom": ["CryptEncrypt", "CryptGenKey", "CryptAcquireContext", "CryptDeriveKey"],
    "download_exec": ["URLDownloadToFile", "ShellExecute", "WinExec", "CreateProcess"],
    "credential_theft": ["CryptUnprotectData", "vaultcli", "LsaRetrievePrivateData"],
}

# Behavioral / textual indicators: category -> list of (pattern, clean label).
# The clean label (our vocabulary) becomes the fact value, never the raw match.
_BEHAVIOR_INDICATORS: dict[str, list[tuple[str, str]]] = {
    "anti_recovery": [
        (r"vssadmin.*delete.*shadows", "vssadmin_shadow_delete"),
        (r"wbadmin\s+delete", "wbadmin_delete"),
        (r"bcdedit.*recoveryenabled\s+no", "bcdedit_disable_recovery"),
    ],
    "persistence": [
        (r"CurrentVersion\\+Run", "run_key"),
        (r"schtasks\s+/create", "scheduled_task"),
    ],
    "ransom_note": [
        (r"your files have been encrypted", "encryption_claim"),
        (r"send\s+[\d.]+\s*(btc|bitcoin)", "btc_ransom_demand"),
        (r"\.locked\b", "locked_extension"),
        (r"decrypt[_ ]instructions", "decrypt_instructions"),
    ],
    "credential_paths": [
        (r"Login Data", "browser_logins"),
        (r"cookies\.sqlite", "browser_cookies"),
        (r"wallet\.dat", "crypto_wallet"),
        (r"\\Electrum\\", "electrum_wallet"),
    ],
}

_URL_RE = re.compile(r"h(?:tt|xx)ps?://[^\s\"']+", re.IGNORECASE)
_MAX_URL_LEN = 100


def extract_indicators(strings: list[str]) -> list[StaticFact]:
    """Scan extracted strings, emit one StaticFact per distinct indicator."""
    blob = "\n".join(strings)
    facts: list[StaticFact] = []
    seen: set[tuple[str, str]] = set()

    def add(fact_type: str, key: str, value: str) -> None:
        if (key, value) not in seen:
            seen.add((key, value))
            facts.append(StaticFact(tool="indicators", fact_type=fact_type, key=key, value=value))

    for capability, names in _API_INDICATORS.items():
        for name in names:
            if re.search(re.escape(name), blob, re.IGNORECASE):
                add("suspicious_api", capability, name)

    for category, entries in _BEHAVIOR_INDICATORS.items():
        for pattern, label in entries:
            if re.search(pattern, blob, re.IGNORECASE):
                add("indicator", category, label)

    for match in _URL_RE.finditer(blob):
        url = match.group()[:_MAX_URL_LEN]
        add("network", "suspicious_url", url)

    return facts
