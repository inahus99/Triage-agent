# Prompt-Injection-Resistant Malware Triage Agent — Architecture

## Problem

Malware triage agents read attacker-controlled content (files, strings, sandbox
output). If that content contains fake instructions, the agent's "loyalty" can
shift from the analyst to the malware itself — the malware skips the user and
takes control of the agent.

## Core principle

Every piece of text is permanently tagged with where it came from. Only the
analyst's fixed instructions may command the agent. Evidence — no matter how
many tools it passes through — can inform a verdict but can never issue a
command.

## Diagram

```mermaid
flowchart TD
    A[Analyst] -->|fixed instructions, never changes| B[Reasoning / Judgment Layer]

    S[Malware Sample] --> Q[Quarantine & Tagging Layer]
    Q -->|tag: UNTRUSTED, persists forever| T1[Static Analysis Tool]
    Q -->|tag: UNTRUSTED| T2[Sandbox / Dynamic Analysis Tool]
    Q -->|tag: UNTRUSTED| T3[Disassembler / Strings Extractor]

    T1 -->|structured facts only:hashes, IOCs, no free text| SF[Structured Fact Store]
    T2 -->|structured facts only:syscalls, network, no free text| SF
    T3 -->|structured facts, tagged excerpts| SF

    SF --> W[Injection Watchdog]
    W -->|scans for fake instructions,encoding tricks, hidden text| F{Injection Detected?}

    F -->|yes| L[Log as Finding:'sample attempted manipulation']
    F -->|no| SF

    L --> B
    SF -->|advisory facts only, still tagged untrusted| B

    B -->|bounded action space only| O1[Write Report Field]
    B --> O2[Assign Severity Score]
    B --> O3[Request Human Review]

    O1 --> R[Final Triage Report]
    O2 --> R
    O3 --> R
    L --> R

    R --> A
```

## Component notes

| Component | Role | Defends against |
|---|---|---|
| Quarantine & Tagging Layer | Wraps every sample-derived byte in an "untrusted evidence" tag before it enters the pipeline | Malware content being read as instructions |
| Structured-output tools | Tools return closed fields (hashes, scores, IOCs) instead of free-form sentences | Tool-output poisoning (injected text riding through a "trusted" tool result) |
| Injection Watchdog | Separate pass that scans extracted text/strings for injection patterns (fake system messages, encoding tricks, unicode lookalikes, buried repetition) | All smuggling techniques — hidden strings, fake metadata, obfuscation, nested injection |
| Reasoning / Judgment Layer | Only place allowed to turn facts into a verdict; system prompt never changes based on sample content | Agent "loyalty" shifting from analyst to malware |
| Bounded Action Space | Agent can only write report fields, assign scores, or escalate — no arbitrary command execution | Successful injection turning into a real-world action |
| Continue-on-detection | Injection attempts are logged as findings, analysis continues using only verified facts, rather than the agent refusing outright | Attacker triggering a denial-of-service by injecting on purpose |

## Data flow guarantee

```
Sample → Quarantine (tag: UNTRUSTED) → Tools (structured output only)
       → Facts (still tagged UNTRUSTED) → Watchdog (flags manipulation)
       → Judgment Layer (only reads facts, only obeys Analyst instructions)
       → Bounded Actions → Report → Analyst
```

At no point does text originating from the sample re-enter the pipeline as an
instruction. The tag is never stripped.
