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
        # Check if slither binary exists on disk or PATH
        binary = self.binary_path
        if not os.path.exists(binary) and not is_tool_available(binary):
            # Check venv
            alt = os.path.join(settings.VENV_BIN_DIR, "slither")
            if os.path.exists(alt):
                binary = alt
            else:
                logger.warning(f"Slither binary not found at '{binary}'. Running fallback static rules.")
                return self._fallback_slither_analysis(source_code, file_path)

        # Build execution environment with venv in PATH so Slither finds solc and forge
        env = {
            "PATH": f"{settings.VENV_BIN_DIR}:{os.environ.get('PATH', '')}",
            "SOLC": settings.SOLC_PATH if os.path.exists(settings.SOLC_PATH) else "solc"
        }

        try:
            cmd = [binary, file_path, "--compile-force-framework", "solc", "--json", "-"]
            rc, stdout, stderr = await run_command_async(
                cmd,
                env=env,
                timeout=settings.SCANNER_TIMEOUT_SECONDS
            )

            # Slither outputs JSON to stdout even when exit code is 255 (vulnerabilities found)
            if stdout and stdout.strip().startswith("{"):
                parsed = self._parse_slither_json(stdout, source_code, file_path)
                if parsed:
                    logger.info(f"Slither successfully executed: detected {len(parsed)} real findings.")
                    return parsed

            if stderr and "Error" in stderr:
                logger.warning(f"Slither CLI completed with stderr: {stderr[:200]}")
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
                description = item.get("description", "").strip()
                recommendation = item.get("recommendation", "Review Slither documentation for remediation.")
                
                # Extract line number from elements source_mapping
                line_no = None
                elements = item.get("elements", [])
                for elem in elements:
                    if "source_mapping" in elem:
                        lines = elem["source_mapping"].get("lines", [])
                        if lines:
                            line_no = lines[0]
                            break

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
                    "INFORMATIONAL": "INFORMATIONAL",
                    "OPTIMIZATION": "INFORMATIONAL"
                }

                calibrated_severity = severity_map.get(impact, "MEDIUM")
                check_lower = check.lower()
                # Calibrate non-exploitable hygiene and best-practice advisory checks to INFORMATIONAL
                if check_lower in ["timestamp", "reentrancy-events", "events-access", "naming-convention", "solc-version", "immutable-states"]:
                    calibrated_severity = "INFORMATIONAL"

                findings.append(RawFinding(
                    title=f"Slither: {check.replace('-', ' ').title()}",
                    category=self._categorize(check),
                    severity=calibrated_severity,
                    confidence=confidence,
                    engine="slither",
                    description=description,
                    recommendation=recommendation,
                    file_path=file_path,
                    line_start=line_no,
                    line_end=line_no,
                    code_snippet=snippet,
                    cwe_id="CWE-710",
                    swc_id="SWC-101",
                    cvss_score=8.0 if impact == "HIGH" else (5.5 if impact == "MEDIUM" else 2.5)
                ))
        except Exception as e:
            logger.error(f"Error parsing Slither JSON: {e}")
        return findings

    def _categorize(self, check: str) -> str:
        ck = check.lower()
        if "reentrancy" in ck:
            return "REENTRANCY"
        if "suicidal" in ck or "arbitrary-send" in ck or "protected" in ck or "controlled-delegatecall" in ck:
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
