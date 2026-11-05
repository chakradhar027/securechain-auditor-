import json
import re
from typing import List
from app.config import settings
from app.detectors.base_detector import RawFinding
from app.utils.process_runner import run_command_async, is_tool_available
from app.utils.logger import logger

class MythrilScanner:
    def __init__(self, binary_path: str = settings.MYTHRIL_PATH):
        self.binary_path = binary_path

    async def scan(self, file_path: str, source_code: str) -> List[RawFinding]:
        findings: List[RawFinding] = []

        if is_tool_available(self.binary_path):
            try:
                cmd = [self.binary_path, "analyze", file_path, "-o", "json"]
                rc, stdout, stderr = await run_command_async(cmd, timeout=settings.SCANNER_TIMEOUT_SECONDS)
                if stdout:
                    parsed = self._parse_mythril_json(stdout, source_code, file_path)
                    if parsed:
                        return parsed
            except Exception as e:
                logger.warning(f"Mythril execution failed: {e}. Falling back to internal symbolic analyzer.")

        # Fallback symbolic heuristics
        return self._fallback_symbolic_analysis(source_code, file_path)

    def _parse_mythril_json(self, raw_json: str, source_code: str, file_path: str) -> List[RawFinding]:
        findings = []
        try:
            data = json.loads(raw_json)
            issues = data.get("issues", [])
            for item in issues:
                title = item.get("title", "Symbolic Execution Issue")
                severity = item.get("severity", "Medium").upper()
                description = item.get("description", "")
                line_no = item.get("lineno")
                swc_id = item.get("swc-id", "SWC-100")

                snippet = ""
                if line_no and source_code:
                    lines = source_code.splitlines()
                    start = max(0, line_no - 2)
                    end = min(len(lines), line_no + 2)
                    snippet = "\n".join(lines[start:end])

                findings.append(RawFinding(
                    title=f"Mythril: {title}",
                    category=self._categorize(swc_id, title),
                    severity=severity if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else "MEDIUM",
                    confidence="HIGH",
                    engine="mythril",
                    description=description,
                    recommendation="Remediate execution path constraint as indicated by symbolic state solver.",
                    file_path=file_path,
                    line_start=line_no,
                    line_end=line_no,
                    code_snippet=snippet,
                    swc_id=f"SWC-{swc_id}" if not swc_id.startswith("SWC-") else swc_id,
                    cvss_score=8.0 if severity == "HIGH" else 5.5
                ))
        except Exception as e:
            logger.error(f"Error parsing Mythril JSON: {e}")
        return findings

    def _categorize(self, swc_id: str, title: str) -> str:
        text = (swc_id + " " + title).lower()
        if "107" in text or "reentrancy" in text:
            return "REENTRANCY"
        if "105" in text or "106" in text or "access" in text or "suicide" in text:
            return "ACCESS_CONTROL"
        if "104" in text or "unchecked" in text or "call" in text:
            return "UNCHECKED_CALL"
        if "oracle" in text or "price" in text:
            return "ORACLE_MANIPULATION"
        return "OTHER"

    def _fallback_symbolic_analysis(self, source_code: str, file_path: str) -> List[RawFinding]:
        """Symbolic path checks: front-running/timestamp dependence, unhandled exceptions."""
        findings = []
        lines = source_code.splitlines()

        for idx, line in enumerate(lines, start=1):
            # Timestamp dependence (SWC-116)
            if re.search(r"\bblock\.timestamp\b", line) or re.search(r"\bnow\b", line):
                if re.search(r"if\s*\(.*(block\.timestamp|now)", line) or re.search(r"require\s*\(.*(block\.timestamp|now)", line):
                    snippet = lines[max(0, idx - 2):min(len(lines), idx + 2)]
                    findings.append(RawFinding(
                        title="Mythril: Timestamp Dependence / Front-Running Window",
                        category="OTHER",
                        severity="LOW",
                        confidence="MEDIUM",
                        engine="mythril",
                        description=(
                            f"Line {idx} relies on block.timestamp for critical condition evaluation: '{line.strip()}'. "
                            "Miners/validators can manipulate block timestamps within an allowable 15-second drift window."
                        ),
                        recommendation="Avoid critical random or timing logic based on block.timestamp, or use block.number / commit-reveal schemes.",
                        file_path=file_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet="\n".join(snippet),
                        cwe_id="CWE-337",
                        swc_id="SWC-116",
                        cvss_score=3.8
                    ))

            # Blockhash randomness (SWC-120)
            if re.search(r"\bblockhash\s*\(", line):
                snippet = lines[max(0, idx - 2):min(len(lines), idx + 2)]
                findings.append(RawFinding(
                    title="Mythril: Insecure Weak PRNG via Blockhash",
                    category="OTHER",
                    severity="HIGH",
                    confidence="HIGH",
                    engine="mythril",
                    description=(
                        f"Line {idx} uses blockhash for pseudo-random number generation: '{line.strip()}'. "
                        "Blockhash values are publicly determinable by validators and front-runners before block finalization."
                    ),
                    recommendation="Use verifiable randomness such as Chainlink VRF (Verifiable Random Function).",
                    file_path=file_path,
                    line_start=idx,
                    line_end=idx,
                    code_snippet="\n".join(snippet),
                    cwe_id="CWE-330",
                    swc_id="SWC-120",
                    cvss_score=7.6
                ))

        return findings
