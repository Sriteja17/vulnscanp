"""Abstract base for all detectors."""
from abc import ABC, abstractmethod
from typing import List
from vulnscan5g.models.finding import Finding


class BaseDetector(ABC):
    name: str = "base"

    @abstractmethod
    def scan(self, code: str, file_path: str, language: str = "c") -> List[Finding]:
        ...

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}>"
