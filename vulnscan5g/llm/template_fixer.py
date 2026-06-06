"""Template-based deterministic fixes for known vulnerability patterns.

Tier 1 of the Hybrid fix strategy — zero LLM calls, instant results.
Each template operates on the exact vulnerable line and produces a safe
replacement without touching any other code.
"""
import re
from dataclasses import dataclass
from typing import Callable, Optional

from vulnscan5g.models.finding import Finding


@dataclass
class FixTemplate:
    """A deterministic fix rule for a known vulnerability pattern."""
    pattern: re.Pattern          # Matches the vulnerable line
    replacer: Callable[[re.Match, str], str]  # (match, full_line) → fixed_line
    applicable_functions: set[str]            # Function names this template handles


# ── Individual fix functions ──────────────────────────────────

def _fix_gets(match: re.Match, line: str) -> str:
    """gets(buf) → fgets(buf, sizeof(buf), stdin)"""
    buf = match.group(1).strip()
    return line[:match.start()] + f"fgets({buf}, sizeof({buf}), stdin)" + line[match.end():]


def _fix_strcpy(match: re.Match, line: str) -> str:
    """strcpy(dst, src) → strncpy(dst, src, sizeof(dst)-1); dst[sizeof(dst)-1]='\\0'"""
    dst = match.group(1).strip()
    src = match.group(2).strip()
    indent = re.match(r"(\s*)", line).group(1)
    return (f"{indent}strncpy({dst}, {src}, sizeof({dst}) - 1);\n"
            f"{indent}{dst}[sizeof({dst}) - 1] = '\\0';")


def _fix_strcat(match: re.Match, line: str) -> str:
    """strcat(dst, src) → strncat(dst, src, sizeof(dst)-strlen(dst)-1)"""
    dst = match.group(1).strip()
    src = match.group(2).strip()
    indent = re.match(r"(\s*)", line).group(1)
    return f"{indent}strncat({dst}, {src}, sizeof({dst}) - strlen({dst}) - 1);"


def _fix_sprintf(match: re.Match, line: str) -> str:
    """sprintf(buf, fmt, ...) → snprintf(buf, sizeof(buf), fmt, ...)"""
    buf = match.group(1).strip()
    rest = match.group(2).strip()
    indent = re.match(r"(\s*)", line).group(1)
    return f"{indent}snprintf({buf}, sizeof({buf}), {rest});"


def _fix_vsprintf(match: re.Match, line: str) -> str:
    """vsprintf(buf, fmt, ap) → vsnprintf(buf, sizeof(buf), fmt, ap)"""
    buf = match.group(1).strip()
    rest = match.group(2).strip()
    indent = re.match(r"(\s*)", line).group(1)
    return f"{indent}vsnprintf({buf}, sizeof({buf}), {rest});"


def _fix_scanf_unbounded(match: re.Match, line: str) -> str:
    """scanf("%s", buf) → scanf("%255s", buf)"""
    return line[:match.start(1)] + "%255s" + line[match.end(1):]


def _fix_wcscpy(match: re.Match, line: str) -> str:
    """wcscpy(dst, src) → wcsncpy(dst, src, sizeof(dst)/sizeof(dst[0])-1)"""
    dst = match.group(1).strip()
    src = match.group(2).strip()
    indent = re.match(r"(\s*)", line).group(1)
    return (f"{indent}wcsncpy({dst}, {src}, sizeof({dst})/sizeof({dst}[0]) - 1);\n"
            f"{indent}{dst}[sizeof({dst})/sizeof({dst}[0]) - 1] = L'\\0';")


# ── Template registry ────────────────────────────────────────

TEMPLATES: list[FixTemplate] = [
    FixTemplate(
        pattern=re.compile(r"\bgets\s*\(\s*([^)]+)\s*\)"),
        replacer=_fix_gets,
        applicable_functions={"gets"},
    ),
    FixTemplate(
        pattern=re.compile(r"\bstrcpy\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)"),
        replacer=_fix_strcpy,
        applicable_functions={"strcpy"},
    ),
    FixTemplate(
        pattern=re.compile(r"\bstrcat\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)"),
        replacer=_fix_strcat,
        applicable_functions={"strcat"},
    ),
    FixTemplate(
        pattern=re.compile(r"\bsprintf\s*\(\s*([^,]+)\s*,\s*(.+)\s*\)"),
        replacer=_fix_sprintf,
        applicable_functions={"sprintf"},
    ),
    FixTemplate(
        pattern=re.compile(r"\bvsprintf\s*\(\s*([^,]+)\s*,\s*(.+)\s*\)"),
        replacer=_fix_vsprintf,
        applicable_functions={"vsprintf"},
    ),
    FixTemplate(
        pattern=re.compile(r'\bscanf\s*\(\s*"[^"]*(%s)[^"]*"'),
        replacer=_fix_scanf_unbounded,
        applicable_functions={"scanf"},
    ),
    FixTemplate(
        pattern=re.compile(r"\bwcscpy\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)"),
        replacer=_fix_wcscpy,
        applicable_functions={"wcscpy"},
    ),
]

# Function names that have a deterministic template
TEMPLATE_FUNCTIONS = set()
for _t in TEMPLATES:
    TEMPLATE_FUNCTIONS.update(_t.applicable_functions)


def try_template_fix(line_text: str, finding: Finding) -> Optional[str]:
    """Attempt a deterministic template fix for the given vulnerable line.

    Returns the fixed line string, or None if no template applies.
    """
    fn = finding.function_name.lower() if finding.function_name else ""

    for tmpl in TEMPLATES:
        if fn and fn not in tmpl.applicable_functions:
            continue
        m = tmpl.pattern.search(line_text)
        if m:
            return tmpl.replacer(m, line_text)

    return None


def can_template_fix(finding: Finding) -> bool:
    """Check if a finding can be fixed by a deterministic template."""
    fn = finding.function_name.lower() if finding.function_name else ""
    return fn in TEMPLATE_FUNCTIONS
