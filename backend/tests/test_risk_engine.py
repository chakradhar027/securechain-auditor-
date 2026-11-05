import pytest
from app.analysis.risk_engine import RiskEngine
from app.analysis.correlation import FindingCorrelator
from app.detectors.base_detector import RawFinding

def test_risk_engine_critical_calculation():
    findings = [
        {
            "title": "Critical Reentrancy",
            "category": "REENTRANCY",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "engine": "custom",
            "description": "State change after call",
            "recommendation": "Fix CEI"
        }
    ]
    fuzz_meta = {"total": 4, "passed": 3, "failed": 1}
    score, level, counts = RiskEngine.calculate_risk(findings, fuzz_meta)
    
    assert level == "CRITICAL"
    assert score >= 80.0
    assert counts["CRITICAL"] == 1

def test_risk_engine_secure_calculation():
    score, level, counts = RiskEngine.calculate_risk([], {"total": 4, "passed": 4, "failed": 0})
    assert level == "SECURE"
    assert score == 0.0
    assert sum(counts.values()) == 0

def test_finding_correlation_deduplication():
    f1 = RawFinding(
        title="Reentrancy Vulnerability",
        category="REENTRANCY",
        severity="HIGH",
        confidence="MEDIUM",
        engine="custom",
        description="CEI issue on line 15",
        recommendation="Use ReentrancyGuard",
        line_start=15,
        line_end=15
    )
    f2 = RawFinding(
        title="Slither: Reentrancy-Eth",
        category="REENTRANCY",
        severity="CRITICAL",
        confidence="HIGH",
        engine="slither",
        description="Reentrancy via send on line 16",
        recommendation="ReentrancyGuard",
        line_start=16,
        line_end=16
    )

    consolidated = FindingCorrelator.correlate([f1, f2])
    assert len(consolidated) == 1
    assert consolidated[0]["severity"] == "CRITICAL"
    assert "consolidated" in consolidated[0]["engine"]
    assert consolidated[0]["confidence"] == "HIGH"
