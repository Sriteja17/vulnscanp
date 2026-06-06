"""Merge and deduplicate findings from multiple detectors.

Two-pass deduplication:
  Pass 1 — Same-spot merge:  file + line + cwe + function
           Collapses regex/AST/tree-sitter hits on the exact same line.
  Pass 2 — Per-file collapse:  file + cwe + function
           Within each file, the same vulnerability type is reported
           only ONCE (first occurrence kept, with all affected lines noted).
"""
import re
from typing import List
from vulnscan5g.models.finding import Finding


# ── CWE alias table ──────────────────────────────────────────
CWE_ALIASES = {
    "CWE-242": "CWE-120",   # gets()   → buffer overflow family
    "CWE-121": "CWE-120",   # stack-based buffer overflow
    "CWE-122": "CWE-120",   # heap-based buffer overflow
}


def _canonical_cwe(cwe_id: str) -> str:
    """Return the canonical CWE for merging purposes."""
    return CWE_ALIASES.get(cwe_id, cwe_id)


# ── function-name extraction ─────────────────────────────────
_FN_PAT = re.compile(r"(\w+)")


def _extract_function(f: Finding) -> str:
    """Best-effort extraction of the target function being flagged."""
    if f.function_name:
        return f.function_name.lower()
    m = _FN_PAT.search(f.vuln_type)
    return m.group(1).lower() if m else ""


# ── detector confidence ranking ──────────────────────────────
_DETECTOR_RANK = {"ast": 3, "tree-sitter": 3, "regex": 1}


def _det_rank(f: Finding) -> int:
    """Higher = more trustworthy."""
    return _DETECTOR_RANK.get(f.detector, 0)


# ── Pass 1: same-spot merge ──────────────────────────────────

def _merge_same_spot(all_findings: List[Finding]) -> List[Finding]:
    """Collapse findings from different detectors on the same line."""
    seen: dict[str, Finding] = {}

    for f in all_findings:
        fn = _extract_function(f)
        canon = _canonical_cwe(f.cwe_id)
        key = f"{f.file_path}:{f.line}:{canon}:{fn}"

        if key in seen:
            existing = seen[key]
            boosted = min(1.0, max(existing.confidence, f.confidence) + 0.15)

            if _det_rank(f) > _det_rank(existing):
                f.confidence = boosted
                f.detector = f"{f.detector}+{existing.detector}"
                seen[key] = f
            else:
                existing.confidence = boosted
                if f.detector not in existing.detector:
                    existing.detector = f"{existing.detector}+{f.detector}"
        else:
            seen[key] = f

    return list(seen.values())


# ── Pass 2: per-file collapse ────────────────────────────────

def _collapse_per_file(findings: List[Finding]) -> List[Finding]:
    """Within each file, keep only ONE finding per vulnerability type.

    When the same vulnerability (e.g. unsafe_strcpy / CWE-120) appears
    on multiple lines in the same file, we keep the highest-confidence
    occurrence and record ALL affected line numbers in the description.
    """
    seen: dict[str, Finding] = {}
    extra_lines: dict[str, list[int]] = {}

    for f in findings:
        fn = _extract_function(f)
        canon = _canonical_cwe(f.cwe_id)
        key = f"{f.file_path}:{canon}:{fn}"

        if key in seen:
            existing = seen[key]
            # Track all affected lines
            extra_lines[key].append(f.line)
            # Keep the higher-confidence / higher-ranked finding
            if _det_rank(f) > _det_rank(existing) or f.confidence > existing.confidence:
                # Preserve collected lines before swapping
                extra_lines[key].append(existing.line)
                extra_lines[key] = [l for l in extra_lines[key] if l != f.line]
                seen[key] = f
            # Merge detector names (avoid duplicates like "ast+ast")
            existing_dets = set(seen[key].detector.split("+"))
            new_dets = set(f.detector.split("+"))
            all_dets = existing_dets | new_dets
            seen[key].detector = "+".join(sorted(all_dets))
            # Boost confidence slightly for repeated occurrences
            seen[key].confidence = min(1.0, seen[key].confidence + 0.05)
        else:
            seen[key] = f
            extra_lines[key] = []

    # Annotate findings with all affected lines
    for key, finding in seen.items():
        other_lines = sorted(set(extra_lines[key]))
        if other_lines:
            all_lines = sorted(set([finding.line] + other_lines))
            lines_str = ", ".join(str(l) for l in all_lines)
            finding.description = (
                f"{finding.description} "
                f"[also on line(s): {lines_str}]"
            )

    return list(seen.values())


# ── public API ────────────────────────────────────────────────

def merge_findings(all_findings: List[Finding]) -> List[Finding]:
    """
    Full two-pass deduplication pipeline.

    Pass 1: Same-spot merge (file + line + cwe + function)
    Pass 2: Per-file collapse (file + cwe + function → one finding per vuln type)
    """
    # Pass 1: cross-detector merge on the same line
    after_pass1 = _merge_same_spot(all_findings)

    # Pass 2: collapse repeated vuln types within the same file
    after_pass2 = _collapse_per_file(after_pass1)

    # Sort by severity (desc) then file then line
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    merged = sorted(
        after_pass2,
        key=lambda x: (sev_order.get(x.severity.value, 9), x.file_path, x.line),
    )
    return merged
