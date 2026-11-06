from typing import Dict

SEVERITY_WEIGHTS: Dict[str, float] = {
    "CRITICAL": 30.0,
    "HIGH": 18.0,
    "MEDIUM": 8.0,
    "LOW": 3.0,
    "INFORMATIONAL": 0.5
}

SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFORMATIONAL": 1
}

def compare_severity(s1: str, s2: str) -> int:
    """Returns > 0 if s1 > s2, < 0 if s1 < s2, 0 if equal."""
    return SEVERITY_ORDER.get(s1.upper(), 0) - SEVERITY_ORDER.get(s2.upper(), 0)

def max_severity(severities: list[str]) -> str:
    """Returns the highest severity from a list."""
    if not severities:
        return "INFORMATIONAL"
    return max(severities, key=lambda s: SEVERITY_ORDER.get(s.upper(), 0))

