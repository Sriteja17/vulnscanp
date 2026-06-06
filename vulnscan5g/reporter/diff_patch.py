"""Diff / patch generation and auto-fix application."""
import os
from typing import Dict, List

from vulnscan5g.models.finding import Finding
from vulnscan5g.preprocess.cleaner import get_raw_snippet


def generate_patch(finding: Finding, original_code: str) -> str:
    """Generate a unified-diff style patch string for one finding."""
    if not finding.llm_fix:
        return ""

    original_snippet = get_raw_snippet(original_code, finding.line, window=5)
    lines_orig = original_snippet.split("\n")
    lines_fix = finding.llm_fix.split("\n")

    start = max(1, finding.line - 5)
    patch_lines = [
        f"--- a/{os.path.basename(finding.file_path)}",
        f"+++ b/{os.path.basename(finding.file_path)}",
        f"@@ -{start},{len(lines_orig)} +{start},{len(lines_fix)} @@",
    ]
    for l in lines_orig:
        patch_lines.append(f"-{l}")
    for l in lines_fix:
        patch_lines.append(f"+{l}")

    return "\n".join(patch_lines)


def apply_fixes(findings: List[Finding], file_codes: Dict[str, str]) -> Dict[str, str]:
    """
    Apply LLM fixes to the source code, producing new code per file.
    Returns dict: {file_path: fixed_code}.
    Only applies fixes where llm_fix is non-empty.
    """
    fixed: Dict[str, str] = {}

    # Group findings by file
    by_file: Dict[str, List[Finding]] = {}
    for f in findings:
        if f.llm_fix:
            by_file.setdefault(f.file_path, []).append(f)

    for fpath, file_findings in by_file.items():
        code = file_codes.get(fpath, "")
        if not code:
            continue
        lines = code.split("\n")

        # Apply fixes bottom-up so line numbers stay valid
        for finding in sorted(file_findings, key=lambda x: x.line, reverse=True):
            start = max(0, finding.line - 6)
            end = min(len(lines), finding.line + 5)
            fix_lines = finding.llm_fix.split("\n")
            lines[start:end] = fix_lines

        fixed[fpath] = "\n".join(lines)

    return fixed


def save_fixed_files(fixed_codes: Dict[str, str], output_dir: str = "fixed_output"):
    """Write fixed code to a separate output folder, preserving filenames.
    
    If multiple source directories have the same filename, creates subdirectories
    to avoid collisions.
    """
    os.makedirs(output_dir, exist_ok=True)
    saved: List[str] = []

    # Detect if there are filename collisions
    fnames = [os.path.basename(fp) for fp in fixed_codes]
    has_collisions = len(fnames) != len(set(fnames))

    for fpath, code in fixed_codes.items():
        fname = os.path.basename(fpath)

        if has_collisions:
            # Use parent directory name as subfolder
            parent = os.path.basename(os.path.dirname(fpath))
            sub_dir = os.path.join(output_dir, parent)
            os.makedirs(sub_dir, exist_ok=True)
            out = os.path.join(sub_dir, fname)
        else:
            out = os.path.join(output_dir, fname)

        with open(out, "w", encoding="utf-8") as f:
            f.write(code)
        saved.append(out)
    return saved

