from typing import List, Dict, Any
from app.detectors.base_detector import RawFinding

def normalize_finding(raw: RawFinding) -> Dict[str, Any]:
    """Ensures consistent naming, capitalized severities, and bounded CVSS scores."""
    severity = raw.severity.upper()
    if severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
        severity = "MEDIUM"

    category = raw.category.upper()
    if category not in ["REENTRANCY", "ACCESS_CONTROL", "UNCHECKED_CALL", "ORACLE_MANIPULATION", "OTHER"]:
        category = "OTHER"

    cvss = raw.cvss_score or 0.0
    if cvss <= 0.0:
        cvss_defaults = {
            "CRITICAL": 9.2,
            "HIGH": 7.8,
            "MEDIUM": 5.4,
            "LOW": 2.8,
            "INFORMATIONAL": 1.0
        }
        cvss = cvss_defaults.get(severity, 5.0)

    return {
        "title": raw.title,
        "category": category,
        "severity": severity,
        "confidence": raw.confidence.upper() if raw.confidence else "MEDIUM",
        "engine": raw.engine,
        "description": raw.description,
        "recommendation": raw.recommendation,
        "file_path": raw.file_path,
        "line_start": raw.line_start,
        "line_end": raw.line_end,
        "code_snippet": raw.code_snippet,
        "cwe_id": raw.cwe_id,
        "swc_id": raw.swc_id,
        "cvss_score": round(cvss, 1)
    }
