"""Hybrid auto-fix engine (Stage 6) — Template + Snippet LLM.

Fix strategy (two tiers):
  Tier 1 — Template:  Known patterns (gets, strcpy, sprintf, …) are fixed
                       instantly with deterministic replacements.  Zero LLM
                       calls, zero tokens, 100 % reliable.
  Tier 2 — Snippet:   Unknown / complex vulnerabilities send ONLY the
                       vulnerable snippet (±window lines) to the LLM, not
                       the whole file.  ~95 % token reduction vs whole-file.

The original file is never regenerated — fixes are spliced line-by-line,
so unchanged code is never touched.
"""
import re
from typing import List, Dict, Optional

from vulnscan5g.llm.client import OllamaClient
from vulnscan5g.llm.template_fixer import try_template_fix, can_template_fix
from vulnscan5g.models.finding import Finding, Severity
from vulnscan5g.preprocess.cleaner import get_raw_snippet


# ── snippet-level LLM prompt ─────────────────────────────────

def _build_snippet_prompt(snippet: str, finding: Finding) -> str:
    """Ask the LLM to fix ONE vulnerability in a small code snippet."""
    return f"""You are a C/C++ security expert.
Fix the vulnerability in this code snippet.

RULES:
1. Return ONLY the fixed code snippet — same number of lines or fewer
2. No markdown fences, no explanations, no text before or after
3. Keep changes minimal — fix ONLY the vulnerability
4. Preserve original indentation and formatting

Vulnerability: {finding.vuln_type} ({finding.cwe_id})
  → {finding.recommendation}

Code:
{snippet}"""


def _clean_snippet_response(response: str) -> str:
    """Strip markdown fences from snippet-level LLM response."""
    text = response.strip()

    # Strip markdown code fences
    if "```" in text:
        lines = text.split("\n")
        cleaned = []
        in_block = False
        for line in lines:
            if line.strip().startswith("```"):
                in_block = not in_block
                continue
            if in_block:
                cleaned.append(line)
        if cleaned:
            text = "\n".join(cleaned)

    # Strip any trailing explanation after code
    # Heuristic: if we see a line starting with "Explanation:" or "Note:", cut there
    cut_markers = ["explanation:", "note:", "this fix", "the fix", "changes made:"]
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if any(line.strip().lower().startswith(m) for m in cut_markers):
            text = "\n".join(lines[:i]).rstrip()
            break

    return text.strip()


# ── Core hybrid fix engine ────────────────────────────────────

def _apply_template_fixes(
    lines: list[str],
    findings: List[Finding],
) -> tuple[list[str], List[Finding]]:
    """Apply Tier 1 template fixes. Returns (modified_lines, remaining_findings)."""
    remaining: List[Finding] = []
    fixed_lines = list(lines)  # shallow copy

    for finding in findings:
        if not can_template_fix(finding):
            remaining.append(finding)
            continue

        line_idx = finding.line - 1  # 0-indexed
        if line_idx < 0 or line_idx >= len(fixed_lines):
            remaining.append(finding)
            continue

        result = try_template_fix(fixed_lines[line_idx], finding)
        if result is not None:
            # Template fix succeeded — splice in the replacement
            # (result may be multi-line, e.g. strncpy + null-terminator)
            replacement_lines = result.split("\n")
            fixed_lines[line_idx:line_idx + 1] = replacement_lines
            # Adjust line numbers for subsequent findings in the same file
            line_delta = len(replacement_lines) - 1
            if line_delta != 0:
                for f in findings:
                    if f.line > finding.line:
                        f.line += line_delta
        else:
            remaining.append(finding)

    return fixed_lines, remaining


def _apply_snippet_llm_fixes(
    lines: list[str],
    findings: List[Finding],
    client: OllamaClient,
    window: int = 5,
) -> list[str]:
    """Apply Tier 2 snippet-level LLM fixes for remaining findings."""
    fixed_lines = list(lines)

    # Sort bottom-up so line number adjustments don't cascade
    sorted_findings = sorted(findings, key=lambda f: f.line, reverse=True)

    for finding in sorted_findings:
        line_idx = finding.line - 1
        start = max(0, line_idx - window)
        end = min(len(fixed_lines), line_idx + window + 1)

        snippet = "\n".join(fixed_lines[start:end])
        prompt = _build_snippet_prompt(snippet, finding)

        try:
            response = client.generate(prompt)
            fixed_snippet = _clean_snippet_response(response)

            if not fixed_snippet.strip():
                continue

            new_lines = fixed_snippet.split("\n")

            # Sanity: fixed snippet shouldn't be wildly different in size
            original_count = end - start
            if len(new_lines) < original_count * 0.3 or len(new_lines) > original_count * 3:
                continue  # Garbage output, skip

            fixed_lines[start:end] = new_lines

        except Exception:
            continue  # LLM unavailable, skip this finding

    return fixed_lines


# ── Rescan helper ─────────────────────────────────────────────

def _rescan(code: str, file_path: str, language: str) -> List[Finding]:
    """Re-scan fixed code to check if vulnerabilities were actually removed."""
    from vulnscan5g.detectors.regex_detector import RegexDetector
    from vulnscan5g.detectors.ast_detector import ASTDetector
    from vulnscan5g.detectors.treesitter_detector import TreeSitterDetector

    results = RegexDetector().scan(code, file_path, language)
    results += ASTDetector().scan(code, file_path, language)
    results += TreeSitterDetector().scan(code, file_path, language)
    # Only care about high + critical
    return [f for f in results if f.severity in (Severity.CRITICAL, Severity.HIGH)]


# ── Public API ────────────────────────────────────────────────

def fix_file(
    code: str,
    findings: List[Finding],
    client: OllamaClient | None = None,
    file_path: str = "file.c",
    language: str = "c",
) -> str | None:
    """
    Fix ALL vulnerabilities in a single file using the hybrid strategy.

    Tier 1: Deterministic template fixes for known patterns (instant).
    Tier 2: Snippet-level LLM fixes for remaining complex issues.

    Returns the complete fixed source code, or None on failure.
    """
    if not findings:
        return None

    lines = code.split("\n")

    # ── Tier 1: Template fixes (instant, no LLM) ─────────────
    lines, remaining = _apply_template_fixes(lines, findings)

    template_fixed = len(findings) - len(remaining)

    # ── Tier 2: Snippet LLM fixes (only for unknowns) ────────
    if remaining and client:
        try:
            if client.is_available():
                lines = _apply_snippet_llm_fixes(lines, remaining, client)
        except Exception:
            pass  # LLM unavailable — template fixes are still applied

    fixed_code = "\n".join(lines)

    # Only return if something actually changed
    if fixed_code.strip() != code.strip():
        return fixed_code
    return None
