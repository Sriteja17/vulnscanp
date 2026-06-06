"""Code preprocessing — comment stripping, normalisation, snippet extraction."""
import re
from typing import Tuple, List
from dataclasses import dataclass, field


@dataclass
class FileMetadata:
    path: str
    total_lines: int
    code_lines: int
    language: str           # "c" or "cpp"
    includes: List[str] = field(default_factory=list)
    functions: List[str] = field(default_factory=list)


# ── transformers ──────────────────────────────────────────────

def strip_comments(code: str) -> str:
    """Remove // and /* */ comments."""
    code = re.sub(r"//.*?$", "", code, flags=re.MULTILINE)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    return code


def _replace_keep_newlines(match) -> str:
    """Replace match content with spaces but keep newlines for line counting."""
    text = match.group(0)
    return "".join("\n" if c == "\n" else " " for c in text)


def neutralize_non_code(code: str) -> str:
    """Replace comments and string literal contents with spaces.

    Preserves all newlines so line numbers remain 1:1 with the original.
    Use this for regex scanning — matches won't fire inside comments or strings.
    """
    # 1. Neutralize block comments /* ... */
    code = re.sub(r"/\*.*?\*/", _replace_keep_newlines, code, flags=re.DOTALL)
    # 2. Neutralize line comments // ...
    code = re.sub(r"//.*?$", _replace_keep_newlines, code, flags=re.MULTILINE)
    # 3. Neutralize string literals "..." (but not the quotes themselves)
    code = re.sub(r'"([^"\\]|\\.)*"', _replace_keep_newlines, code)
    # 4. Neutralize char literals '...'
    code = re.sub(r"'([^'\\]|\\.)*'", _replace_keep_newlines, code)
    return code


def strip_preprocessor(code: str) -> str:
    return re.sub(r"^\s*#.*?$", "", code, flags=re.MULTILINE)


def preprocess(code: str, comments: bool = True, preprocessor: bool = False) -> str:
    if comments:
        code = strip_comments(code)
    if preprocessor:
        code = strip_preprocessor(code)
    return "\n".join(l.rstrip() for l in code.split("\n"))


# ── snippet helpers ───────────────────────────────────────────

def get_snippet(code: str, line: int, window: int = 5) -> Tuple[str, int, int]:
    """Return (numbered_snippet, start_line_1idx, end_line_1idx)."""
    lines = code.split("\n")
    start = max(0, line - window - 1)
    end = min(len(lines), line + window)
    snippet = "\n".join(f"{i+1:4d} | {lines[i]}" for i in range(start, end))
    return snippet, start + 1, end


def get_raw_snippet(code: str, line: int, window: int = 5) -> str:
    lines = code.split("\n")
    start = max(0, line - window - 1)
    end = min(len(lines), line + window)
    return "\n".join(lines[start:end])


# ── metadata ──────────────────────────────────────────────────

def _extract_includes(code: str) -> List[str]:
    return re.findall(r'#include\s*[<"]([^>"]+)[>"]', code)


def _extract_functions(code: str) -> List[str]:
    clean = strip_comments(code)
    matches = re.findall(r"\b(\w+)\s*\([^)]*\)\s*\{", clean)
    keywords = {"if", "else", "for", "while", "switch", "do", "return", "sizeof", "typedef"}
    return [m for m in matches if m not in keywords]


def extract_metadata(path: str, code: str, language: str) -> FileMetadata:
    lines = code.split("\n")
    clean = strip_comments(code)
    code_lines = sum(1 for l in clean.split("\n") if l.strip())
    return FileMetadata(
        path=path,
        total_lines=len(lines),
        code_lines=code_lines,
        language=language,
        includes=_extract_includes(code),
        functions=_extract_functions(code),
    )
