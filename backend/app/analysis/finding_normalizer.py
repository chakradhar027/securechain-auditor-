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

    # Contextual Exploitability Assessment
    desc = raw.description
    if "Exploitability Assessment:" not in desc and "[Exploitability Assessment]" not in desc:
        if severity in ["CRITICAL", "HIGH"]:
            exploitability_tag = "\n\n[Exploitability Assessment]: High Risk / Active Vulnerability. This finding represents an exploitable security flaw capable of causing asset loss, unauthorized state corruption, or privilege escalation."
        elif severity == "MEDIUM":
            exploitability_tag = "\n\n[Exploitability Assessment]: Medium Risk / Conditional Vulnerability. Exploitation requires specific execution paths, pre-conditions, or external contract interaction."
        elif severity == "LOW":
            exploitability_tag = "\n\n[Exploitability Assessment]: Low Risk / Minor Vulnerability. Impact is limited in scope and does not directly permit fund theft or unauthorized takeover."
        else:
            exploitability_tag = "\n\n[Exploitability Assessment]: Informational / Non-Exploitable Advisory. Compiler warning or code-hygiene notice; does not represent an exploitable vulnerability."
        desc = f"{desc}{exploitability_tag}"

    return {
        "title": raw.title,
        "category": category,
        "severity": severity,
        "confidence": raw.confidence.upper() if raw.confidence else "MEDIUM",
        "engine": raw.engine,
        "description": desc,
        "recommendation": raw.recommendation,
        "file_path": raw.file_path,
        "line_start": raw.line_start,
        "line_end": raw.line_end,
        "code_snippet": raw.code_snippet,
        "cwe_id": raw.cwe_id,
        "swc_id": raw.swc_id,
        "cvss_score": round(cvss, 1)
    }

