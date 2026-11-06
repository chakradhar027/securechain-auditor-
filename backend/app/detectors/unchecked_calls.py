import re
from typing import List
from app.detectors.base_detector import BaseDetector, RawFinding

class UncheckedCallsDetector(BaseDetector):
    def __init__(self):
        super().__init__("UncheckedCallsDetector")

    def detect(self, source_code: str, file_path: str = "") -> List[RawFinding]:
        findings: List[RawFinding] = []
        lines = source_code.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue

            # Check for naked .send(...)
            if re.search(r"\b[a-zA-Z0-9_\.]+\.send\s*\(", line):
                # If not inside a require or boolean assignment
                if not re.search(r"\brequire\s*\([^;]*\.send\(", line) and not re.search(r"\bbool\s+[a-zA-Z0-9_]+\s*=", line):
                    snippet = self.extract_snippet(source_code, idx, context_lines=2)
                    findings.append(RawFinding(
                        title="Unchecked Return Value of Low-Level 'send'",
                        category="UNCHECKED_CALL",
                        severity="MEDIUM",
                        confidence="HIGH",
                        engine="custom",
                        description=(
                            f"On line {idx}, the contract executes 'send' without verifying its return value: '{stripped}'. "
                            "If the recipient contract throws or consumes more than 2300 gas, the call will fail silently "
                            "and execution will proceed as if funds were transferred."
                        ),
                        recommendation="Wrap the call in 'require(recipient.send(amount), \"Send failed\");' or use call with proper error handling.",
                        file_path=file_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=snippet,
                        cwe_id="CWE-252",
                        swc_id="SWC-104",
                        cvss_score=6.2
                    ))

            # Check for low-level .call without checking return value
            if (".call{" in line or ".call(" in line) and "bytes" not in line:
                # Check if boolean return is captured: (bool success, ) = ... or require(...)
                has_bool_capture = bool(
                    re.search(r"\(\s*bool\s+[a-zA-Z0-9_]*\s*,", line) or
                    re.search(r"\bbool\s+[a-zA-Z0-9_]+\s*=", line) or
                    re.search(r"\brequire\s*\(.*\.call", line)
                )

                if not has_bool_capture:
                    snippet = self.extract_snippet(source_code, idx, context_lines=2)
                    findings.append(RawFinding(
                        title="Unchecked Return Value of Low-Level 'call'",
                        category="UNCHECKED_CALL",
                        severity="HIGH",
                        confidence="HIGH",
                        engine="custom",
                        description=(
                            f"On line {idx}, an external low-level '.call' is made without capturing or checking its return status: '{stripped}'. "
                            "If the target reverts or execution runs out of gas, the caller contract continues normal execution unaware of the failure."
                        ),
                        recommendation="Capture the boolean return value and revert on failure: '(bool success, ) = target.call{value: ...}(\"\"); require(success, \"Call failed\");'.",
                        file_path=file_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=snippet,
                        cwe_id="CWE-252",
                        swc_id="SWC-104",
                        cvss_score=7.1
                    ))

            # Check for raw ERC20 transfer / transferFrom without SafeERC20
            if (re.search(r"\bIERC20\b", source_code) or re.search(r"\bERC20\b", source_code)) and "SafeERC20" not in source_code:
                if re.search(r"\.[a-zA-Z0-9_]*transfer(From)?\s*\(", line) and not re.search(r"\brequire\s*\(", line):
                    # Check if line does not assign boolean
                    if not re.search(r"\bbool\s+[a-zA-Z0-9_]+\s*=", line):
                        snippet = self.extract_snippet(source_code, idx, context_lines=2)
                        findings.append(RawFinding(
                            title="Unchecked ERC-20 Transfer Return Value",
                            category="UNCHECKED_CALL",
                            severity="MEDIUM",
                            confidence="MEDIUM",
                            engine="custom",
                            description=(
                                f"Line {idx} executes token transfer without verifying the returned boolean or using SafeERC20: '{stripped}'. "
                                "Non-standard ERC-20 tokens (e.g. USDT) may return false or no return data, causing silent transfer failures."
                            ),
                            recommendation="Adopt OpenZeppelin's 'SafeERC20' library using 'safeTransfer' and 'safeTransferFrom'.",
                            file_path=file_path,
                            line_start=idx,
                            line_end=idx,
                            code_snippet=snippet,
                            cwe_id="CWE-252",
                            swc_id="SWC-104",
                            cvss_score=5.8
                        ))

        return findings

