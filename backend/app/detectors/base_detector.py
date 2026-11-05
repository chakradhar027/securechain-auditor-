from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class RawFinding:
    title: str
    category: str  # REENTRANCY, ACCESS_CONTROL, UNCHECKED_CALL, ORACLE_MANIPULATION, OTHER
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    confidence: str # HIGH, MEDIUM, LOW
    engine: str
    description: str
    recommendation: str
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None
    cwe_id: Optional[str] = None
    swc_id: Optional[str] = None
    cvss_score: Optional[float] = 0.0

class BaseDetector(ABC):
    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def detect(self, source_code: str, file_path: str = "") -> List[RawFinding]:
        """Analyzes Solidity code and returns a list of raw findings."""
        pass

    def extract_snippet(self, source_code: str, line_no: int, context_lines: int = 3) -> str:
        """Extracts code lines around line_no for evidence."""
        lines = source_code.splitlines()
        start = max(0, line_no - context_lines - 1)
        end = min(len(lines), line_no + context_lines)
        snippet = []
        for i in range(start, end):
            prefix = ">> " if (i + 1) == line_no else "   "
            snippet.append(f"{prefix}{i+1}: {lines[i]}")
        return "\n".join(snippet)
