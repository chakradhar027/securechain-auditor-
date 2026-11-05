from typing import List, Dict, Any
from app.analysis.finding_normalizer import normalize_finding
from app.analysis.severity import max_severity, compare_severity
from app.detectors.base_detector import RawFinding

class FindingCorrelator:
    @staticmethod
    def correlate(raw_findings: List[RawFinding]) -> List[Dict[str, Any]]:
        """
        Groups and merges findings from multiple engines pointing to the same issue.
        """
        normalized = [normalize_finding(rf) for rf in raw_findings]
        consolidated: List[Dict[str, Any]] = []

        for item in normalized:
            matched = False
            for existing in consolidated:
                if FindingCorrelator._is_duplicate(existing, item):
                    FindingCorrelator._merge_finding(existing, item)
                    matched = True
                    break
            if not matched:
                # Add copy to consolidated list
                item_copy = dict(item)
                item_copy["engines_corroborating"] = [item["engine"]]
                consolidated.append(item_copy)

        # Final pass: format engine display name
        for item in consolidated:
            engines = list(set(item.get("engines_corroborating", [item["engine"]])))
            if len(engines) > 1:
                item["engine"] = f"consolidated ({', '.join(sorted(engines))})"
                item["confidence"] = "HIGH"
                item["title"] = f"[Multi-Engine] {item['title'].replace('Slither: ', '').replace('Mythril: ', '')}"

        return consolidated

    @staticmethod
    def _is_duplicate(f1: Dict[str, Any], f2: Dict[str, Any]) -> bool:
        # Check category match
        if f1["category"] != f2["category"]:
            return False

        # If both have line numbers, check proximity within 4 lines
        l1 = f1.get("line_start")
        l2 = f2.get("line_start")
        if l1 is not None and l2 is not None:
            if abs(l1 - l2) <= 4:
                return True

        # Check title similarity
        t1 = f1["title"].lower().replace("slither: ", "").replace("mythril: ", "")
        t2 = f2["title"].lower().replace("slither: ", "").replace("mythril: ", "")
        if t1 in t2 or t2 in t1:
            return True

        return False

    @staticmethod
    def _merge_finding(target: Dict[str, Any], incoming: Dict[str, Any]):
        # Elevate severity to highest
        target["severity"] = max_severity([target["severity"], incoming["severity"]])
        
        # Maximize CVSS
        target["cvss_score"] = max(target.get("cvss_score", 0.0), incoming.get("cvss_score", 0.0))

        # Add engine to corroborators
        engines = target.setdefault("engines_corroborating", [target["engine"]])
        if incoming["engine"] not in engines:
            engines.append(incoming["engine"])

        # Retain richest code snippet
        if not target.get("code_snippet") and incoming.get("code_snippet"):
            target["code_snippet"] = incoming["code_snippet"]

        # Append additional detail if informative
        if incoming["description"] not in target["description"]:
            target["description"] += f"\n[Corroboration from {incoming['engine']}]: {incoming['description']}"
