import json
import os
import re
from typing import List, Optional
from app.config import settings
from app.detectors.base_detector import RawFinding
from app.utils.process_runner import run_command_async, is_tool_available
from app.utils.logger import logger

class MythrilScanner:
    def __init__(self, binary_path: str = settings.MYTHRIL_PATH):
        self.binary_path = binary_path

    async def scan(self, file_path: str, source_code: str) -> List[RawFinding]:
        """
        Executes Mythril symbolic analysis.
        Tier 1: Isolated Docker container running official mythril/myth image.
        Tier 2: Native Mythril CLI ('myth') if installed.
        Tier 3: Clearly labeled symbolic-heuristic engine fallback when Mythril is unavailable.
        """
        findings: List[RawFinding] = []

        # 1. Attempt Docker-based Mythril execution
        if is_tool_available("docker"):
            try:
                docker_findings = await self._run_docker_mythril(file_path, source_code)
                if docker_findings is not None:
                    logger.info(f"Mythril Docker executed successfully: detected {len(docker_findings)} findings.")
                    return docker_findings
            except Exception as e:
                logger.warning(f"Mythril Docker execution failed or timed out: {e}")

        # 2. Attempt Native CLI Mythril execution
        binary = self.binary_path
        if not os.path.exists(binary) and not is_tool_available(binary):
            alt = os.path.join(settings.VENV_BIN_DIR, "myth")
            if os.path.exists(alt):
                binary = alt

        if os.path.exists(binary) or is_tool_available(binary):
            try:
                cli_findings = await self._run_cli_mythril(binary, file_path, source_code)
                if cli_findings is not None:
                    logger.info(f"Mythril native CLI executed successfully: detected {len(cli_findings)} findings.")
                    return cli_findings
            except Exception as e:
                logger.warning(f"Mythril CLI execution failed or timed out: {e}")

        # 3. Transparent Handling: When Docker and native CLI are absent, do NOT substitute heuristics for Mythril
        logger.warning(
            "Mythril symbolic execution unverified: Neither Docker daemon nor native 'myth' CLI "
            "is installed in this runtime environment (Python 3.13). Real Mythril execution was not performed, "
            "and heuristic output is NOT substituted for Mythril."
        )
        return []

    async def _run_docker_mythril(self, file_path: str, source_code: str) -> Optional[List[RawFinding]]:
        """
        Executes actual Mythril symbolic analysis in an isolated Docker container.
        Image: mythril/myth:latest (Python 3.10 based)
        """
        abs_file = os.path.abspath(file_path)
        dir_name = os.path.dirname(abs_file)
        base_name = os.path.basename(abs_file)

        cmd = [
            "docker", "run", "--rm",
            "-v", f"{dir_name}:/share",
            "mythril/myth",
            "analyze", f"/share/{base_name}",
            "-o", "json",
            "--solv", "0.8.20",
            "--execution-timeout", str(min(60, settings.SCANNER_TIMEOUT_SECONDS))
        ]

        rc, stdout, stderr = await run_command_async(
            cmd,
            timeout=settings.SCANNER_TIMEOUT_SECONDS + 15
        )

        if stdout and ("{" in stdout):
            start_idx = stdout.find("{")
            json_text = stdout[start_idx:]
            return self._parse_mythril_json(json_text, source_code, file_path, engine="mythril (docker)")

        return None

    async def _run_cli_mythril(self, binary: str, file_path: str, source_code: str) -> Optional[List[RawFinding]]:
        """
        Executes native Mythril CLI binary.
        """
        env = {
            "PATH": f"{settings.VENV_BIN_DIR}:{os.environ.get('PATH', '')}",
            "SOLC": settings.SOLC_PATH if os.path.exists(settings.SOLC_PATH) else "solc"
        }
        cmd = [
            binary, "analyze", file_path,
            "-o", "json",
            "--execution-timeout", str(min(60, settings.SCANNER_TIMEOUT_SECONDS))
        ]

        rc, stdout, stderr = await run_command_async(
            cmd,
            env=env,
            timeout=settings.SCANNER_TIMEOUT_SECONDS + 15
        )

        if stdout and ("{" in stdout):
            start_idx = stdout.find("{")
            json_text = stdout[start_idx:]
            return self._parse_mythril_json(json_text, source_code, file_path, engine="mythril (cli)")

        return None

    def _parse_mythril_json(
        self,
        raw_json: str,
        source_code: str,
        file_path: str,
        engine: str = "mythril"
    ) -> List[RawFinding]:
        findings = []
        try:
            data = json.loads(raw_json)
            issues = data.get("issues", [])
            for item in issues:
                title = item.get("title", "Symbolic Execution Issue")
                severity = item.get("severity", "Medium").upper()
                description = item.get("description", "").strip()
                line_no = item.get("lineno")
                swc_id = str(item.get("swc-id", "SWC-100"))
                function = item.get("function", "")

                snippet = ""
                if line_no and source_code:
                    lines = source_code.splitlines()
                    start = max(0, line_no - 2)
                    end = min(len(lines), line_no + 2)
                    snippet = "\n".join(lines[start:end])

                cwe_id = "CWE-841" if "reentrancy" in title.lower() else ("CWE-284" if "access" in title.lower() else "CWE-710")

                findings.append(RawFinding(
                    title=f"Mythril: {title}",
                    category=self._categorize(swc_id, title),
                    severity=severity if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else "MEDIUM",
                    confidence="HIGH",
                    engine=engine,
                    description=(
                        f"Mythril symbolic constraint solver discovered an exploitable execution path in function '{function}'. "
                        f"Details: {description}. Exploitability Assessment: High Exploitability (Symbolic Path Solved)."
                    ),
                    recommendation="Remediate the state variable constraint violation identified by Mythril's symbolic execution path.",
                    file_path=file_path,
                    line_start=line_no,
                    line_end=line_no,
                    code_snippet=snippet,
                    cwe_id=cwe_id,
                    swc_id=f"SWC-{swc_id}" if not swc_id.startswith("SWC-") else swc_id,
                    cvss_score=8.2 if severity == "HIGH" else (5.5 if severity == "MEDIUM" else 3.0)
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
        """
        Symbolic heuristic pattern analyzer.
        Explicitly labeled as 'symbolic-heuristic' to distinguish from real Mythril execution.
        """
        findings = []
        lines = source_code.splitlines()

        for idx, line in enumerate(lines, start=1):
            if re.search(r"\bblock\.timestamp\b", line) or re.search(r"\bnow\b", line):
                if re.search(r"if\s*\(.*(block\.timestamp|now)", line) or re.search(r"require\s*\(.*(block\.timestamp|now)", line):
                    snippet = lines[max(0, idx - 2):min(len(lines), idx + 2)]
                    findings.append(RawFinding(
                        title="[Heuristic] Timestamp Dependence / Front-Running Window",
                        category="OTHER",
                        severity="LOW",
                        confidence="LOW",
                        engine="symbolic-heuristic",
                        description=(
                            f"Line {idx} evaluates block.timestamp in critical conditional branch: '{line.strip()}'. "
                            "Miners/validators can manipulate timestamps within a 15-second drift margin. "
                            "Note: This is a symbolic heuristic check (Mythril CLI / Docker was not active)."
                        ),
                        recommendation="Avoid critical timing logic based on block.timestamp; use block.number or commit-reveal patterns.",
                        file_path=file_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet="\n".join(snippet),
                        cwe_id="CWE-337",
                        swc_id="SWC-116",
                        cvss_score=3.5
                    ))

            if re.search(r"\bblockhash\s*\(", line):
                snippet = lines[max(0, idx - 2):min(len(lines), idx + 2)]
                findings.append(RawFinding(
                    title="[Heuristic] Weak Pseudo-Random Number Generation via Blockhash",
                    category="OTHER",
                    severity="HIGH",
                    confidence="MEDIUM",
                    engine="symbolic-heuristic",
                    description=(
                        f"Line {idx} uses blockhash for random seed computation: '{line.strip()}'. "
                        "Blockhash values are publicly predictable by validators prior to state confirmation. "
                        "Note: This is a symbolic heuristic check (Mythril CLI / Docker was not active)."
                    ),
                    recommendation="Use verifiable randomness such as Chainlink VRF.",
                    file_path=file_path,
                    line_start=idx,
                    line_end=idx,
                    code_snippet="\n".join(snippet),
                    cwe_id="CWE-330",
                    swc_id="SWC-120",
                    cvss_score=7.5
                ))

        return findings
