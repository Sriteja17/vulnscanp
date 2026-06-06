"""Core data model for a vulnerability finding."""
from dataclasses import dataclass, asdict, field
from typing import Optional
from enum import Enum
import json


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other):
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)


@dataclass
class Finding:
    """Represents a single vulnerability finding."""

    file_path: str
    line: int
    column: int = 0
    vuln_type: str = ""
    rule_id: str = ""
    cwe_id: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.5
    description: str = ""
    recommendation: str = ""
    snippet: str = ""
    detector: str = ""          # "regex" | "ast"
    function_name: str = ""

    # LLM enrichment (populated later)
    llm_confirmed: Optional[bool] = None
    llm_confidence: Optional[float] = None
    llm_explanation: str = ""
    llm_fix: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
