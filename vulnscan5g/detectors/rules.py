"""All regex-based vulnerability rules organised by CWE category."""
from dataclasses import dataclass, field
from typing import List
from vulnscan5g.models.finding import Severity


@dataclass
class Rule:
    id: str
    name: str
    pattern: str
    cwe_id: str
    severity: Severity
    description: str
    recommendation: str
    languages: List[str] = field(default_factory=lambda: ["c", "cpp"])


# ═══════════════════════════════════════════════════════════════
#  BUFFER OVERFLOW  (CWE-120 / 121 / 122 / 242)
# ═══════════════════════════════════════════════════════════════
BUFFER_OVERFLOW: List[Rule] = [
    Rule("BOF-001", "gets() usage",
         r"\bgets\s*\(", "CWE-242", Severity.CRITICAL,
         "gets() has no bounds checking — guaranteed buffer overflow",
         "Replace with fgets(buf, sizeof(buf), stdin)"),
    Rule("BOF-002", "strcpy() without bounds",
         r"\bstrcpy\s*\(", "CWE-120", Severity.HIGH,
         "strcpy() copies without size limit",
         "Use strncpy() or strlcpy() with explicit size"),
    Rule("BOF-003", "strcat() without bounds",
         r"\bstrcat\s*\(", "CWE-120", Severity.HIGH,
         "strcat() concatenates without size limit",
         "Use strncat() or strlcat() with explicit size"),
    Rule("BOF-004", "sprintf() without bounds",
         r"\bsprintf\s*\(", "CWE-120", Severity.HIGH,
         "sprintf() writes without size limit",
         "Use snprintf() with explicit buffer size"),
    Rule("BOF-005", "scanf %s without width",
         r'\bscanf\s*\(\s*"[^"]*%s', "CWE-120", Severity.HIGH,
         "scanf with %s reads unbounded input",
         'Use %Ns with explicit width, e.g. %255s'),
    Rule("BOF-006", "vsprintf() without bounds",
         r"\bvsprintf\s*\(", "CWE-120", Severity.HIGH,
         "vsprintf() writes without size limit",
         "Use vsnprintf() with explicit buffer size"),
    Rule("BOF-007", "wcscpy() without bounds",
         r"\bwcscpy\s*\(", "CWE-120", Severity.HIGH,
         "wcscpy() copies wide strings without bounds",
         "Use wcsncpy() with explicit size"),
]

# ═══════════════════════════════════════════════════════════════
#  FORMAT STRING  (CWE-134)
# ═══════════════════════════════════════════════════════════════
FORMAT_STRING: List[Rule] = [
    Rule("FMT-001", "printf() with variable format",
         r"\bprintf\s*\(\s*[a-zA-Z_]\w*\s*\)", "CWE-134", Severity.HIGH,
         "printf() called with variable as format string",
         'Use printf("%s", variable) instead'),
    Rule("FMT-002", "fprintf() with variable format",
         r"\bfprintf\s*\(\s*\w+\s*,\s*[a-zA-Z_]\w*\s*\)", "CWE-134", Severity.HIGH,
         "fprintf() with variable format string",
         'Use fprintf(stream, "%s", variable)'),
    Rule("FMT-003", "syslog() with variable format",
         r"\bsyslog\s*\(\s*\w+\s*,\s*[a-zA-Z_]\w*\s*\)", "CWE-134", Severity.HIGH,
         "syslog() with variable format string",
         'Use syslog(priority, "%s", variable)'),
]

# ═══════════════════════════════════════════════════════════════
#  COMMAND INJECTION  (CWE-78)
# ═══════════════════════════════════════════════════════════════
COMMAND_INJECTION: List[Rule] = [
    Rule("CMD-001", "system() call",
         r"\bsystem\s*\(", "CWE-78", Severity.CRITICAL,
         "system() executes shell commands — command injection risk",
         "Use exec family (execvp) with explicit argument arrays"),
    Rule("CMD-002", "popen() call",
         r"\bpopen\s*\(", "CWE-78", Severity.HIGH,
         "popen() executes shell commands",
         "Use fork/exec with explicit argument arrays"),
]

# ═══════════════════════════════════════════════════════════════
#  USE-AFTER-FREE / DOUBLE-FREE  (CWE-416 / 415)
# ═══════════════════════════════════════════════════════════════
USE_AFTER_FREE: List[Rule] = [
    Rule("UAF-001", "free() without NULL assignment",
         r"\bfree\s*\(\s*(\w+)\s*\)\s*;(?!\s*\1\s*=\s*NULL)", "CWE-416", Severity.HIGH,
         "Pointer not set to NULL after free()",
         "Set pointer to NULL immediately after free()"),
    Rule("UAF-002", "Potential double free",
         r"\bfree\s*\(\s*(\w+)\s*\)[\s\S]{0,200}?\bfree\s*\(\s*\1\s*\)", "CWE-415", Severity.CRITICAL,
         "Same pointer freed twice — heap corruption",
         "Set pointer to NULL after first free"),
]

# ═══════════════════════════════════════════════════════════════
#  INTEGER OVERFLOW  (CWE-190)
# ═══════════════════════════════════════════════════════════════
INTEGER_OVERFLOW: List[Rule] = [
    Rule("INT-001", "malloc with arithmetic",
         r"\bmalloc\s*\(\s*\w+\s*[*+]\s*\w+\s*\)", "CWE-190", Severity.HIGH,
         "Arithmetic in malloc size can integer-overflow",
         "Check for overflow before multiplication, or use calloc()"),
    Rule("INT-002", "realloc with arithmetic",
         r"\brealloc\s*\(\s*\w+\s*,\s*\w+\s*[*+]\s*\w+\s*\)", "CWE-190", Severity.HIGH,
         "Arithmetic in realloc size can integer-overflow",
         "Validate new size before realloc"),
]

# ═══════════════════════════════════════════════════════════════
#  RACE CONDITION / TOCTOU  (CWE-362 / 367)
# ═══════════════════════════════════════════════════════════════
RACE_CONDITION: List[Rule] = [
    Rule("RACE-001", "TOCTOU: access() then open()",
         r"\baccess\s*\([^)]+\)[\s\S]{0,300}?\bopen\s*\(", "CWE-367", Severity.MEDIUM,
         "Time-of-check / time-of-use race between access() and open()",
         "Use open() with appropriate flags instead"),
    Rule("RACE-002", "TOCTOU: stat() then open()",
         r"\bstat\s*\([^)]+\)[\s\S]{0,300}?\bopen\s*\(", "CWE-367", Severity.MEDIUM,
         "stat() + open() is a TOCTOU race condition",
         "Use fstat() after open() instead"),
]

# ═══════════════════════════════════════════════════════════════
#  NULL POINTER DEREF  (CWE-476)
# ═══════════════════════════════════════════════════════════════
NULL_DEREF: List[Rule] = [
    Rule("NULL-001", "malloc without NULL check",
         r"\b(\w+)\s*=\s*malloc\s*\([^)]+\)\s*;(?!\s*if\s*\(\s*\1)", "CWE-476", Severity.MEDIUM,
         "malloc() return not checked for NULL",
         "Always check malloc() return value before use"),
    Rule("NULL-002", "calloc without NULL check",
         r"\b(\w+)\s*=\s*calloc\s*\([^)]+\)\s*;(?!\s*if\s*\(\s*\1)", "CWE-476", Severity.MEDIUM,
         "calloc() return not checked for NULL",
         "Always check calloc() return value before use"),
    Rule("NULL-003", "realloc without NULL check",
         r"\b(\w+)\s*=\s*realloc\s*\([^)]+\)\s*;(?!\s*if\s*\(\s*\1)", "CWE-476", Severity.MEDIUM,
         "realloc() return not checked for NULL",
         "Check realloc() return; assign to temp pointer first"),
]

# ═══════════════════════════════════════════════════════════════
#  MEMORY LEAK  (CWE-401)
# ═══════════════════════════════════════════════════════════════
MEMORY_LEAK: List[Rule] = [
    Rule("LEAK-001", "malloc in loop without free",
         r"(for|while)\s*\([^)]*\)\s*\{[^}]*\bmalloc\s*\([^)]*\)(?![^}]*\bfree\s*\()",
         "CWE-401", Severity.MEDIUM,
         "malloc() inside loop without matching free()",
         "Ensure every malloc inside a loop has a corresponding free"),
]

# ═══════════════════════════════════════════════════════════════
#  UNINITIALIZED MEMORY  (CWE-908)
# ═══════════════════════════════════════════════════════════════
UNINITIALIZED: List[Rule] = [
    Rule("UNINIT-001", "Uninitialized stack buffer",
         r"\bchar\s+\w+\s*\[\s*\d+\s*\]\s*;",
         "CWE-908", Severity.LOW,
         "Stack char buffer declared without initialisation — may leak data",
         "Initialise with = {0} or memset()"),
]

# ═══════════════════════════════════════════════════════════════
#  UNSAFE MEMORY OPS
# ═══════════════════════════════════════════════════════════════
UNSAFE_MEMORY: List[Rule] = [
    Rule("MEM-001", "memcpy with variable size",
         r"\bmemcpy\s*\(\s*\w+\s*,\s*\w+\s*,\s*[a-zA-Z_]\w*\s*\)", "CWE-120", Severity.MEDIUM,
         "memcpy() with variable size — verify bounds",
         "Validate size parameter against destination buffer"),
    Rule("MEM-002", "memmove with variable size",
         r"\bmemmove\s*\(\s*\w+\s*,\s*\w+\s*,\s*[a-zA-Z_]\w*\s*\)", "CWE-120", Severity.MEDIUM,
         "memmove() with variable size — verify bounds",
         "Validate size parameter against destination buffer"),
]


# ── master list ───────────────────────────────────────────────
ALL_RULES: List[Rule] = (
    BUFFER_OVERFLOW
    + FORMAT_STRING
    + COMMAND_INJECTION
    + USE_AFTER_FREE
    + INTEGER_OVERFLOW
    + RACE_CONDITION
    + NULL_DEREF
    + MEMORY_LEAK
    + UNINITIALIZED
    + UNSAFE_MEMORY
)
