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
                item_copy = dict(item)
                item_copy["engines_corroborating"] = [item["engine"]]
                consolidated.append(item_copy)

        # Final pass: format engine display name
        for item in consolidated:
            engines = list(set(item.get("engines_corroborating", [item["engine"]])))
            if len(engines) > 1:
                item["engine"] = f"consolidated ({', '.join(sorted(engines))})"
                item["confidence"] = "HIGH"
                cleaned_title = item['title'].replace('Slither: ', '').replace('Mythril: ', '')
                if not cleaned_title.startswith("[Multi-Engine]"):
                    item["title"] = f"[Multi-Engine] {cleaned_title}"

        return consolidated

    @staticmethod
    def _is_duplicate(f1: Dict[str, Any], f2: Dict[str, Any]) -> bool:
        # Check category match
        if f1["category"] != f2["category"]:
            return False

        # An INFORMATIONAL finding must NEVER be merged into an active vulnerability
        is_info1 = (f1.get("severity", "").upper() == "INFORMATIONAL")
        is_info2 = (f2.get("severity", "").upper() == "INFORMATIONAL")
        if is_info1 != is_info2:
            return False

        # Findings from the same engine with different titles are distinct checks, not duplicates
        if f1.get("engine") == f2.get("engine") and f1.get("title") != f2.get("title"):
            return False

        t1 = f1["title"].lower().replace("slither: ", "").replace("mythril: ", "").replace("[multi-engine] ", "")
        t2 = f2["title"].lower().replace("slither: ", "").replace("mythril: ", "").replace("[multi-engine] ", "")

        # For OTHER category, require title keyword overlap
        if f1["category"] == "OTHER":
            return t1 in t2 or t2 in t1

        # If both have line numbers, check proximity within 4 lines
        l1 = f1.get("line_start")
        l2 = f2.get("line_start")
        if l1 is not None and l2 is not None:
            if abs(l1 - l2) <= 4:
                return True

        # Check title similarity
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

        # Clean incoming description: strip trailing Exploitability Assessment tag so it doesn't pollute the target
        import re
        cleaned_incoming_desc = re.sub(r"\n*\[Exploitability Assessment\]:[^\n]*(\n[^\n]*)*$", "", incoming["description"]).strip()
        if cleaned_incoming_desc and cleaned_incoming_desc not in target["description"]:
            if incoming["engine"] != target["engine"]:
                target["description"] += f"\n[Corroboration from {incoming['engine']}]: {cleaned_incoming_desc}"
            else:
                target["description"] += f"\n{cleaned_incoming_desc}"
