"""Tree-sitter based vulnerability detector — full AST for C and C++.

Parser priority strategy:
  • C   files → pycparser (primary) ; tree-sitter only when pycparser is absent
  • C++ files → tree-sitter (exclusive; pycparser cannot parse C++)
"""
from typing import List

from vulnscan5g.detectors.base import BaseDetector
from vulnscan5g.models.finding import Finding, Severity

try:
    import tree_sitter_c as tsc
    import tree_sitter_cpp as tscpp
    from tree_sitter import Language, Parser

    C_LANG = Language(tsc.language())
    CPP_LANG = Language(tscpp.language())
    TREE_SITTER_AVAILABLE = True
except Exception:
    TREE_SITTER_AVAILABLE = False


# ── unsafe function lookup ────────────────────────────────────
UNSAFE_FUNCS = {
    "gets":     ("CWE-242", Severity.CRITICAL,  "gets() has no bounds checking",
                 "Replace with fgets(buf, sizeof(buf), stdin)"),
    "strcpy":   ("CWE-120", Severity.HIGH,      "strcpy() copies without size limit",
                 "Use strncpy() or strlcpy() with explicit size"),
    "strcat":   ("CWE-120", Severity.HIGH,      "strcat() concatenates without size limit",
                 "Use strncat() or strlcat() with explicit size"),
    "sprintf":  ("CWE-120", Severity.HIGH,      "sprintf() writes without size limit",
                 "Use snprintf() with explicit buffer size"),
    "vsprintf": ("CWE-120", Severity.HIGH,      "vsprintf() writes without size limit",
                 "Use vsnprintf() with explicit buffer size"),
    "wcscpy":   ("CWE-120", Severity.HIGH,      "wcscpy() copies wide strings without bounds",
                 "Use wcsncpy() with explicit size"),
}

EXEC_FUNCS = {
    "system": ("CWE-78", Severity.CRITICAL, "system() executes shell commands",
               "Use exec family (execvp) with explicit args"),
    "popen":  ("CWE-78", Severity.HIGH,     "popen() executes shell commands",
               "Use fork/exec with explicit argument arrays"),
}

ALLOC_FUNCS = {"malloc", "calloc", "realloc"}

FORMAT_FUNCS = {"printf", "fprintf", "syslog"}


def _get_function_name(node) -> str:
    """Extract function name from a call_expression node."""
    func_node = node.child_by_field_name("function")
    if func_node is None:
        return ""
    # Simple identifier: printf(...)
    if func_node.type == "identifier":
        return func_node.text.decode("utf-8")
    # Member access: obj.method() or obj->method()
    if func_node.type in ("field_expression", "qualified_identifier"):
        # Get the last identifier
        for child in func_node.children:
            if child.type == "field_identifier" or child.type == "identifier":
                return child.text.decode("utf-8")
    return ""


def _get_arguments(node) -> list:
    """Get argument nodes from a call_expression."""
    args_node = node.child_by_field_name("arguments")
    if args_node is None:
        return []
    return [c for c in args_node.children if c.type not in ("(", ")", ",")]


def _check_format_string_vuln(node, fn_name: str) -> bool:
    """Check if a format function is called with a variable format string."""
    args = _get_arguments(node)
    if not args:
        return False
    # For fprintf, the format string is the 2nd arg
    fmt_idx = 1 if fn_name == "fprintf" else 0
    if fmt_idx >= len(args):
        return False
    fmt_arg = args[fmt_idx]
    # If it's a string_literal, it's safe
    return fmt_arg.type != "string_literal"


def _check_null_after_alloc(node, source_code: bytes) -> bool:
    """Check if an alloc result is null-checked (heuristic)."""
    # Look at the parent — if it's inside an if(), it's checked
    parent = node.parent
    while parent:
        if parent.type == "if_statement":
            return True
        if parent.type in ("function_definition", "compound_statement"):
            break
        parent = parent.parent
    return False


class TreeSitterDetector(BaseDetector):
    name = "tree-sitter"

    def scan(self, code: str, file_path: str, language: str = "c") -> List[Finding]:
        if not TREE_SITTER_AVAILABLE:
            return []

        # ── Parser priority: defer C files to pycparser when it is available ──
        if language == "c":
            try:
                from vulnscan5g.detectors.ast_detector import PYCPARSER_AVAILABLE
            except ImportError:
                PYCPARSER_AVAILABLE = False
            if PYCPARSER_AVAILABLE:
                # pycparser handles C — skip tree-sitter to avoid duplicates
                return []

        findings: List[Finding] = []
        source = code.encode("utf-8")

        parser = Parser()
        if language == "cpp":
            parser.language = CPP_LANG
        else:
            parser.language = C_LANG

        tree = parser.parse(source)
        self._walk(tree.root_node, file_path, source, findings, language)
        return findings

    def _walk(self, node, file_path: str, source: bytes, findings: list, language: str):
        """Recursively walk the AST and check for vulnerabilities."""

        if node.type == "call_expression":
            fn = _get_function_name(node)
            line = node.start_point[0] + 1  # tree-sitter is 0-indexed

            # Unsafe copy/buffer functions
            if fn in UNSAFE_FUNCS:
                cwe, sev, desc, rec = UNSAFE_FUNCS[fn]
                findings.append(Finding(
                    file_path=file_path, line=line,
                    vuln_type=f"unsafe_{fn}()", rule_id=f"TS-BOF-{fn}",
                    cwe_id=cwe, severity=sev, confidence=0.85,
                    description=desc, recommendation=rec,
                    detector=self.name, function_name=fn,
                ))

            # Command execution
            elif fn in EXEC_FUNCS:
                cwe, sev, desc, rec = EXEC_FUNCS[fn]
                findings.append(Finding(
                    file_path=file_path, line=line,
                    vuln_type=f"command_exec_{fn}()", rule_id=f"TS-CMD-{fn}",
                    cwe_id=cwe, severity=sev, confidence=0.85,
                    description=desc, recommendation=rec,
                    detector=self.name, function_name=fn,
                ))

            # Format string vulnerabilities
            elif fn in FORMAT_FUNCS:
                if _check_format_string_vuln(node, fn):
                    findings.append(Finding(
                        file_path=file_path, line=line,
                        vuln_type=f"format_string_{fn}()", rule_id=f"TS-FMT-{fn}",
                        cwe_id="CWE-134", severity=Severity.HIGH, confidence=0.8,
                        description=f"{fn}() with non-literal format string",
                        recommendation=f'Use {fn}("%s", var) instead',
                        detector=self.name, function_name=fn,
                    ))

            # Unchecked alloc
            elif fn in ALLOC_FUNCS:
                if not _check_null_after_alloc(node, source):
                    findings.append(Finding(
                        file_path=file_path, line=line,
                        vuln_type=f"unchecked_{fn}()", rule_id=f"TS-NULL-{fn}",
                        cwe_id="CWE-476", severity=Severity.MEDIUM, confidence=0.7,
                        description=f"{fn}() return value may not be NULL-checked",
                        recommendation=f"Always check {fn}() return for NULL",
                        detector=self.name, function_name=fn,
                    ))

        # C++ specific: raw new without try/catch or nothrow
        if language == "cpp" and node.type == "new_expression":
            line = node.start_point[0] + 1
            text = node.text.decode("utf-8") if node.text else ""
            if "nothrow" not in text:
                findings.append(Finding(
                    file_path=file_path, line=line,
                    vuln_type="unchecked_new", rule_id="TS-CPP-NEW",
                    cwe_id="CWE-476", severity=Severity.MEDIUM, confidence=0.6,
                    description="new without nothrow may throw on allocation failure",
                    recommendation="Use std::nothrow or wrap in try/catch",
                    detector=self.name,
                ))

        # C++ specific: delete without nullptr assignment
        if language == "cpp" and node.type == "delete_expression":
            line = node.start_point[0] + 1
            findings.append(Finding(
                file_path=file_path, line=line,
                vuln_type="delete_without_nullptr", rule_id="TS-CPP-DEL",
                cwe_id="CWE-416", severity=Severity.MEDIUM, confidence=0.6,
                description="Pointer not set to nullptr after delete",
                recommendation="Set pointer to nullptr after delete",
                detector=self.name,
            ))

        # Recurse into children
        for child in node.children:
            self._walk(child, file_path, source, findings, language)
