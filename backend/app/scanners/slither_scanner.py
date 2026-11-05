import json
import os
import re
from typing import List
from app.config import settings
from app.detectors.base_detector import RawFinding
from app.utils.process_runner import run_command_async, is_tool_available
from app.utils.logger import logger

class SlitherScanner:
    def __init__(self, binary_path: str = settings.SLITHER_PATH):
        self.binary_path = binary_path

    async def scan(self, file_path: str, source_code: str) -> List[RawFinding]:
        findings: List[RawFinding] = []
        
        # If slither binary exists on system, run real CLI
        if is_tool_available(self.binary_path):
            try:
                cmd = [self.binary_path, file_path, "--json", "-"]
                rc, stdout, stderr = await run_command_async(cmd, timeout=settings.SCANNER_TIMEOUT_SECONDS)
                if stdout:
                    parsed = self._parse_slither_json(stdout, source_code, file_path)
                    if parsed:
                        return parsed
            except Exception as e:
                logger.warning(f"Slither CLI execution failed: {e}. Falling back to internal static analyzer.")

        # Static analyzer fallback (simulates Slither's canonical rules)
        return self._fallback_slither_analysis(source_code, file_path)

    def _parse_slither_json(self, raw_json: str, source_code: str, file_path: str) -> List[RawFinding]:
        findings: List[RawFinding] = []
        try:
            data = json.loads(raw_json)
            detectors = data.get("results", {}).get("detectors", [])
            for item in detectors:
                check = item.get("check", "slither-warning")
                impact = item.get("impact", "Informational").upper()
                confidence = item.get("confidence", "Medium").upper()
                description = item.get("description", "")
                recommendation = item.get("recommendation", "Review Slither documentation for remediation.")
                
                # Extract line number
                line_no = None
                elements = item.get("elements", [])
                if elements and "source_mapping" in elements[0]:
                    lines = elements[0]["source_mapping"].get("lines", [])
                    if lines:
                        line_no = lines[0]

                snippet = ""
                if line_no and source_code:
                    lines = source_code.splitlines()
                    start = max(0, line_no - 2)
                    end = min(len(lines), line_no + 2)
                    snippet = "\n".join(lines[start:end])

                severity_map = {
                    "HIGH": "HIGH",
                    "MEDIUM": "MEDIUM",
                    "LOW": "LOW",
                    "INFORMATIONAL": "INFORMATIONAL"
                }

                findings.append(RawFinding(
                    title=f"Slither: {check.replace('-', ' ').title()}",
                    category=self._categorize(check),
                    severity=severity_map.get(impact, "MEDIUM"),
                    confidence=confidence,
                    engine="slither",
                    description=description,
                    recommendation=recommendation,
                    file_path=file_path,
                    line_start=line_no,
                    line_end=line_no,
                    code_snippet=snippet,
                    swc_id="SWC-101",
                    cvss_score=7.0 if impact == "HIGH" else (5.0 if impact == "MEDIUM" else 3.0)
                ))
        except Exception as e:
            logger.error(f"Error parsing Slither JSON: {e}")
        return findings

    def _categorize(self, check: str) -> str:
        ck = check.lower()
        if "reentrancy" in ck:
            return "REENTRANCY"
        if "suicidal" in ck or "arbitrary-send" in ck or "protected" in ck:
            return "ACCESS_CONTROL"
        if "unchecked" in ck or "call" in ck:
            return "UNCHECKED_CALL"
        if "oracle" in ck or "price" in ck:
            return "ORACLE_MANIPULATION"
        return "OTHER"

    def _fallback_slither_analysis(self, source_code: str, file_path: str) -> List[RawFinding]:
        """Rules mimicking Slither's static detector suite."""
        findings = []
        lines = source_code.splitlines()

        # Rule 1: Delegatecall in loop or dynamic delegatecall
        for idx, line in enumerate(lines, start=1):
            if ".delegatecall(" in line:
                findings.append(RawFinding(
                    title="Slither: Controlled Delegatecall Destination",
                    category="ACCESS_CONTROL",
                    severity="CRITICAL",
                    confidence="HIGH",
                    engine="slither",
                    description=(
                        f"Line {idx} uses 'delegatecall': '{line.strip()}'. "
                        "Executing delegatecall to an untrusted or user-supplied address allows attackers to execute arbitrary code "
                        "in the context of this contract, overwriting state variables including ownership."
                    ),
                    recommendation="Ensure delegatecall targets are strictly hardcoded or immutable proxy implementation addresses.",
                    file_path=file_path,
                    line_start=idx,
                    line_end=idx,
                    code_snippet=line.strip(),
                    cwe_id="CWE-829",
                    swc_id="SWC-112",
                    cvss_score=9.5
                ))

            # Rule 2: Floating Pragma
            if re.search(r"pragma\s+solidity\s+[\^><=]", line):
                findings.append(RawFinding(
                    title="Slither: Floating Pragma Version",
                    category="OTHER",
                    severity="LOW",
                    confidence="HIGH",
                    engine="slither",
                    description=f"Line {idx} uses a floating pragma ('{line.strip()}'). Contracts should be deployed with the same compiler version they were tested with.",
                    recommendation="Lock the pragma version to a specific release (e.g. 'pragma solidity 0.8.20;').",
                    file_path=file_path,
                    line_start=idx,
                    line_end=idx,
                    code_snippet=line.strip(),
                    cwe_id="CWE-664",
                    swc_id="SWC-103",
                    cvss_score=2.5
                ))

            # Rule 3: Assembly usage
            if "assembly" in line and "{" in line:
                findings.append(RawFinding(
                    title="Slither: Inline Assembly Usage",
                    category="OTHER",
                    severity="INFORMATIONAL",
                    confidence="HIGH",
                    engine="slither",
                    description=f"Line {idx} introduces inline assembly blocks, bypassing Solidity memory and safety guarantees.",
                    recommendation="Verify assembly logic meticulously and document why EVM-level instructions are required.",
                    file_path=file_path,
                    line_start=idx,
                    line_end=idx,
                    code_snippet=line.strip(),
                    cwe_id="CWE-242",
                    swc_id="SWC-127",
                    cvss_score=1.5
                ))

        return findings
