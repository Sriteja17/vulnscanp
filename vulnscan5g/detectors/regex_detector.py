"""Regex-based vulnerability detector — fast first-pass for all C/C++ files."""
import re
from typing import List

from vulnscan5g.detectors.base import BaseDetector
from vulnscan5g.detectors.rules import ALL_RULES, Rule
from vulnscan5g.models.finding import Finding
from vulnscan5g.preprocess.cleaner import neutralize_non_code


class RegexDetector(BaseDetector):
    name = "regex"

    # Pattern to extract function name from the regex match text
    _FN_RE = re.compile(r"\b(\w+)\s*\(")

    def scan(self, code: str, file_path: str, language: str = "c") -> List[Finding]:
        # Neutralize comments & strings — preserves line numbers
        neutralized = neutralize_non_code(code)
        findings: List[Finding] = []

        for rule in ALL_RULES:
            if language not in rule.languages:
                continue
            try:
                for m in re.finditer(rule.pattern, neutralized):
                    line = neutralized[: m.start()].count("\n") + 1
                    # Extract the target function name from matched text
                    fn_match = self._FN_RE.search(m.group(0))
                    fn_name = fn_match.group(1) if fn_match else ""
                    findings.append(
                        Finding(
                            file_path=file_path,
                            line=line,
                            vuln_type=rule.name,
                            rule_id=rule.id,
                            cwe_id=rule.cwe_id,
                            severity=rule.severity,
                            confidence=0.6,
                            description=rule.description,
                            recommendation=rule.recommendation,
                            detector=self.name,
                            function_name=fn_name,
                        )
                    )
            except re.error:
                continue

        return findings
