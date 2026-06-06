"""AST-based vulnerability detector using pycparser (C files only)."""
from typing import List

from vulnscan5g.detectors.base import BaseDetector
from vulnscan5g.models.finding import Finding, Severity

try:
    from pycparser import c_parser, c_ast

    PYCPARSER_AVAILABLE = True
except ImportError:
    PYCPARSER_AVAILABLE = False


# ── fake type declarations so pycparser can parse without real headers ──
_FAKE_HEADERS = """
typedef int size_t;
typedef int ssize_t;
typedef int FILE;
typedef long int64_t;
typedef unsigned long uint64_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef char int8_t;
typedef unsigned char uint8_t;
typedef int wchar_t;
typedef int bool;
typedef void* va_list;

int printf(const char *, ...);
int fprintf(void *, const char *, ...);
int sprintf(char *, const char *, ...);
int snprintf(char *, int, const char *, ...);
int scanf(const char *, ...);
int sscanf(const char *, const char *, ...);
int strcpy(char *, const char *);
int strncpy(char *, const char *, int);
int strcat(char *, const char *);
int strncat(char *, const char *, int);
int strcmp(const char *, const char *);
int strlen(const char *);
char *gets(char *);
char *fgets(char *, int, void *);
void *malloc(int);
void *calloc(int, int);
void *realloc(void *, int);
void free(void *);
void *memcpy(void *, const void *, int);
void *memset(void *, int, int);
void *memmove(void *, const void *, int);
int system(const char *);
void *popen(const char *, const char *);
int atoi(const char *);
long atol(const char *);
void exit(int);
void abort(void);
"""

import re


def _keep_newlines(match) -> str:
    """Replace matched text with empty lines, preserving newline count."""
    return "\n" * match.group(0).count("\n")


def _clean_for_parser(code: str) -> str:
    """Strip preprocessor directives and comments for pycparser.

    Preserves all newlines so line numbers stay 1:1 with the original file.
    """
    # Block comments /* ... */ — may span multiple lines
    code = re.sub(r"/\*.*?\*/", _keep_newlines, code, flags=re.DOTALL)
    # Line comments //
    code = re.sub(r"//.*?$", "", code, flags=re.MULTILINE)
    # Preprocessor directives — blank the content but keep the newline
    # [^\S\n]* matches horizontal whitespace only (not newlines)
    code = re.sub(r"^[^\S\n]*#.*?$", "", code, flags=re.MULTILINE)
    return code


# ── AST visitor ───────────────────────────────────────────────
if PYCPARSER_AVAILABLE:

    class _VulnVisitor(c_ast.NodeVisitor):
        UNSAFE_COPY = {"strcpy", "strcat", "sprintf", "gets", "vsprintf", "wcscpy"}
        MEMORY_OPS = {"memcpy", "memmove", "strncpy"}
        INPUT_FUNCS = {"scanf", "gets", "sscanf"}
        EXEC_FUNCS = {"system", "popen"}
        FORMAT_FUNCS = {"printf", "fprintf", "syslog"}
        ALLOC_FUNCS = {"malloc", "calloc", "realloc"}

        def __init__(self, line_offset: int = 0) -> None:
            self.issues: List[Finding] = []
            self._file_path = ""
            self._line_offset = line_offset

        def _add(self, node, vuln_type: str, cwe: str, sev: Severity, desc: str, rec: str, rule_id: str):
            raw_line = node.coord.line if node.coord else 0
            actual_line = max(1, raw_line - self._line_offset)
            self.issues.append(
                Finding(
                    file_path=self._file_path,
                    line=actual_line,
                    vuln_type=vuln_type,
                    rule_id=rule_id,
                    cwe_id=cwe,
                    severity=sev,
                    confidence=0.8,
                    description=desc,
                    recommendation=rec,
                    detector="ast",
                    function_name=node.name.name if hasattr(node.name, "name") else "",
                )
            )

        def visit_FuncCall(self, node):
            if not hasattr(node.name, "name"):
                self.generic_visit(node)
                return

            fn = node.name.name

            if fn in self.UNSAFE_COPY:
                self._add(node, f"unsafe_{fn}()", "CWE-120", Severity.HIGH,
                          f"{fn}() is an unsafe copy function", f"Replace {fn}() with bounds-checked alternative",
                          f"AST-BOF-{fn}")

            elif fn in self.EXEC_FUNCS:
                self._add(node, f"command_exec_{fn}()", "CWE-78", Severity.CRITICAL,
                          f"{fn}() executes shell commands", "Use exec family with explicit args",
                          f"AST-CMD-{fn}")

            elif fn in self.FORMAT_FUNCS:
                # check if first real arg is a variable (not string literal)
                try:
                    args = node.args.exprs if node.args else []
                    target = args[1] if fn == "fprintf" else args[0]
                    if not isinstance(target, c_ast.Constant):
                        self._add(node, f"format_string_{fn}()", "CWE-134", Severity.HIGH,
                                  f"{fn}() with non-literal format string",
                                  f'Use {fn}("%s", var) instead',
                                  f"AST-FMT-{fn}")
                except (IndexError, AttributeError):
                    pass

            elif fn in self.INPUT_FUNCS:
                self._add(node, f"unsafe_input_{fn}()", "CWE-120", Severity.HIGH,
                          f"{fn}() can read unbounded input", "Validate/limit input size",
                          f"AST-INP-{fn}")

            elif fn in self.ALLOC_FUNCS:
                # Warn about unchecked alloc (heuristic: no surrounding if)
                self._add(node, f"unchecked_{fn}()", "CWE-476", Severity.MEDIUM,
                          f"{fn}() return value may not be NULL-checked",
                          f"Always check {fn}() return for NULL",
                          f"AST-NULL-{fn}")

            self.generic_visit(node)


class ASTDetector(BaseDetector):
    name = "ast"

    def scan(self, code: str, file_path: str, language: str = "c") -> List[Finding]:
        if not PYCPARSER_AVAILABLE:
            return []
        # pycparser only handles C
        if language != "c":
            return []

        try:
            cleaned = _clean_for_parser(code)
            header_line_count = _FAKE_HEADERS.count("\n")
            full = _FAKE_HEADERS + cleaned
            parser = c_parser.CParser()
            ast = parser.parse(full)

            visitor = _VulnVisitor(line_offset=header_line_count)
            visitor._file_path = file_path
            visitor.visit(ast)
            return visitor.issues
        except Exception:
            # If parsing fails, silently return empty — regex detector covers us
            return []
