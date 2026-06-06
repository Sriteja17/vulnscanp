"""All prompt templates for LLM reasoning and fixing."""


def reason_prompt(snippet: str, vuln_type: str, cwe_id: str) -> str:
    return f"""You are a C/C++ security expert.

Analyze this code snippet for the reported vulnerability.

Respond in EXACTLY this format (no extra text):
Confirmed: YES or NO
Vulnerability: <one-line summary>
Reason: <1-2 sentences explaining why this is dangerous>
Severity: CRITICAL / HIGH / MEDIUM / LOW

Code:
{snippet}

Reported issue: {vuln_type} ({cwe_id})
"""


def fix_prompt(snippet: str, vuln_type: str, cwe_id: str) -> str:
    return f"""You are a C/C++ security expert.

Fix the vulnerability in this code snippet.

Rules:
- Return ONLY the corrected code
- No explanations, no markdown fences
- Keep changes minimal — fix only the vulnerability
- Preserve original logic and formatting

Code:
{snippet}

Vulnerability: {vuln_type} ({cwe_id})
"""


def batch_reason_prompt(snippet: str, issues: list[dict]) -> str:
    issue_lines = "\n".join(
        f"  - Line {i['line']}: {i['type']} ({i['cwe']})" for i in issues
    )
    return f"""You are a C/C++ security expert.

Analyze these reported vulnerabilities in the code below.
For EACH issue, respond on one line in this format:
Line <N>: CONFIRMED/REJECTED — <short reason>

Issues:
{issue_lines}

Code:
{snippet}
"""
