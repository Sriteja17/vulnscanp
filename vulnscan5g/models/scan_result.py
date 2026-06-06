"""Container for an entire scan run."""
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime
import json

from .finding import Finding, Severity


@dataclass
class ScanResult:
    """Aggregates all findings from a scan."""

    target_path: str
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_with_issues: int = 0
    scan_start: datetime = field(default_factory=datetime.now)
    scan_end: Optional[datetime] = None
    errors: List[str] = field(default_factory=list)

    # ── helpers ───────────────────────────────────────────────
    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def duration(self) -> float:
        if self.scan_end:
            return (self.scan_end - self.scan_start).total_seconds()
        return 0.0

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

    def add(self, finding: Finding):
        self.findings.append(finding)

    def by_file(self) -> Dict[str, List[Finding]]:
        groups: Dict[str, List[Finding]] = {}
        for f in self.findings:
            groups.setdefault(f.file_path, []).append(f)
        return groups

    def summary(self) -> Dict:
        return {
            "target": self.target_path,
            "files_scanned": self.files_scanned,
            "total_findings": self.total,
            "critical": self.count(Severity.CRITICAL),
            "high": self.count(Severity.HIGH),
            "medium": self.count(Severity.MEDIUM),
            "low": self.count(Severity.LOW),
            "info": self.count(Severity.INFO),
            "duration_seconds": round(self.duration, 2),
        }

    def to_json(self) -> str:
        return json.dumps(
            {"summary": self.summary(),
             "findings": [f.to_dict() for f in self.findings],
             "errors": self.errors},
            indent=2, default=str,
        )
