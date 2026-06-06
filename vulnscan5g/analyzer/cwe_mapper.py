"""CWE enrichment — maps CWE IDs to human-readable names and URLs."""
from typing import List
from vulnscan5g.models.finding import Finding

CWE_DB = {
    "CWE-78":  "Improper Neutralization of Special Elements used in an OS Command (Command Injection)",
    "CWE-120": "Buffer Copy without Checking Size of Input (Classic Buffer Overflow)",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-134": "Use of Externally-Controlled Format String",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-242": "Use of Inherently Dangerous Function",
    "CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)",
    "CWE-367": "Time-of-check Time-of-use (TOCTOU) Race Condition",
    "CWE-401": "Missing Release of Memory after Effective Lifetime (Memory Leak)",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-908": "Use of Uninitialized Resource",
}


def cwe_name(cwe_id: str) -> str:
    return CWE_DB.get(cwe_id, cwe_id)


def cwe_url(cwe_id: str) -> str:
    num = cwe_id.replace("CWE-", "")
    return f"https://cwe.mitre.org/data/definitions/{num}.html"


def enrich_cwe(findings: List[Finding]) -> List[Finding]:
    """Add CWE description into the finding description if not already there."""
    for f in findings:
        if f.cwe_id and f.cwe_id in CWE_DB:
            name = CWE_DB[f.cwe_id]
            if name not in f.description:
                f.description = f"[{f.cwe_id}] {name} — {f.description}"
    return findings
