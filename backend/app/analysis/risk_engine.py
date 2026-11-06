from typing import List, Dict, Any, Tuple
from app.analysis.severity import SEVERITY_WEIGHTS

class RiskEngine:
    @staticmethod
    def calculate_risk(
        consolidated_findings: List[Dict[str, Any]],
        fuzz_meta: Dict[str, Any]
    ) -> Tuple[float, str, Dict[str, int]]:
        """
        Calculates: (risk_score, risk_level, severity_counts)
        """
        counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFORMATIONAL": 0
        }

        for f in consolidated_findings:
            sev = f.get("severity", "MEDIUM").upper()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["MEDIUM"] += 1

        fuzz_failed = fuzz_meta.get("failed", 0)

        # Raw score calculation - informational advisories do not penalize risk score
        raw_score = (
            counts["CRITICAL"] * 35.0 +
            counts["HIGH"] * 20.0 +
            counts["MEDIUM"] * 8.0 +
            counts["LOW"] * 3.0 +
            fuzz_failed * 15.0
        )

        # Baseline overrides
        if counts["CRITICAL"] > 0:
            score = max(80.0, min(100.0, raw_score))
            level = "CRITICAL"
        elif counts["HIGH"] > 0 or fuzz_failed > 0:
            score = max(55.0, min(79.9, raw_score))
            level = "HIGH"
        elif counts["MEDIUM"] > 0:
            score = max(25.0, min(54.9, raw_score))
            level = "MEDIUM"
        elif counts["LOW"] > 0:
            score = max(5.0, min(24.9, raw_score))
            level = "LOW"
        else:
            # Informational findings represent compiler/code-style suggestions and do not represent exploitable risk.
            score = 0.0
            level = "SECURE"

        return round(score, 1), level, counts

