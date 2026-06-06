"""Filter findings by minimum severity threshold."""
from typing import List
from vulnscan5g.models.finding import Finding, Severity
from vulnscan5g.config import SEVERITY_ORDER


def filter_by_severity(findings: List[Finding], min_severity: str = "low") -> List[Finding]:
    threshold = SEVERITY_ORDER.get(min_severity, 0)
    return [f for f in findings if SEVERITY_ORDER.get(f.severity.value, 0) >= threshold]
