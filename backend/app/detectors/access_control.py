import re
from typing import List
from app.detectors.base_detector import BaseDetector, RawFinding

class AccessControlDetector(BaseDetector):
    def __init__(self):
        super().__init__("AccessControlDetector")

    def detect(self, source_code: str, file_path: str = "") -> List[RawFinding]:
        findings: List[RawFinding] = []
        lines = source_code.splitlines()

        # Sensitive function names that typically require administrative authorization
        sensitive_keywords = [
            "emergencywithdraw", "drain", "withdrawall", "adminwithdraw", "sweep",
            "transferownership", "setowner", "changeadmin",
            "mint", "burn", "destroy", "kill", "selfdestruct", "upgrade",
            "setfee", "setrate", "pause", "unpause", "emergency"
        ]

        # Authorization patterns
        auth_patterns = [
            r"\bonlyOwner\b", r"\bonlyAdmin\b", r"\bonlyRole\b",
            r"\bauth\b", r"\brequire\s*\(\s*msg\.sender\s*==",
            r"\brequire\s*\(\s*owner\s*==\s*msg\.sender",
            r"\bif\s*\(\s*msg\.sender\s*!=\s*owner",
            r"\b_checkOwner\b", r"\b_checkRole\b"
        ]

        func_regex = re.compile(
            r"function\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)\s*([^{]*)\{",
            re.MULTILINE
        )

        in_function = False
        func_name = ""
        func_start_line = 0
        func_lines = []
        brace_depth = 0
        header_text = ""

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue

            # Check for tx.origin authorization
            if re.search(r"\btx\.origin\s*==", line) or re.search(r"==\s*tx\.origin\b", line):
                snippet = self.extract_snippet(source_code, idx, context_lines=2)
                findings.append(RawFinding(
                    title="Vulnerable Authorization via 'tx.origin'",
                    category="ACCESS_CONTROL",
                    severity="HIGH",
                    confidence="HIGH",
                    engine="custom",
                    description=(
                        f"Line {idx} uses 'tx.origin' for access control check: '{stripped}'. "
                        "Using tx.origin allows malicious contracts to conduct phishing attacks where an authorized "
                        "user is tricked into invoking an attacker contract that forwards calls to this contract."
                    ),
                    recommendation="Replace 'tx.origin' with 'msg.sender' to ensure direct caller authentication.",
                    file_path=file_path,
                    line_start=idx,
                    line_end=idx,
                    code_snippet=snippet,
                    cwe_id="CWE-477",
                    swc_id="SWC-115",
                    cvss_score=7.4
                ))

            # Check for selfdestruct / suicide
            if re.search(r"\bselfdestruct\s*\(", line) or re.search(r"\bsuicide\s*\(", line):
                snippet = self.extract_snippet(source_code, idx, context_lines=2)
                findings.append(RawFinding(
                    title="Dangerous Operation: selfdestruct Present",
                    category="ACCESS_CONTROL",
                    severity="CRITICAL",
                    confidence="HIGH",
                    engine="custom",
                    description=(
                        f"Line {idx} contains 'selfdestruct': '{stripped}'. "
                        "If access control is missing or bypassed, any attacker can permanently destroy the contract and burn trapped assets."
                    ),
                    recommendation="Remove 'selfdestruct' (deprecated in EIP-6049/EIP-6780) or guard with multi-sig/timelock access controls.",
                    file_path=file_path,
                    line_start=idx,
                    line_end=idx,
                    code_snippet=snippet,
                    cwe_id="CWE-284",
                    swc_id="SWC-106",
                    cvss_score=9.1
                ))

            # Function tracking
            match = func_regex.search(line)
            if match and not in_function:
                in_function = True
                func_name = match.group(1)
                func_start_line = idx
                header_text = line
                func_lines = [(idx, line)]
                brace_depth = line.count("{") - line.count("}")
                continue

            if in_function:
                func_lines.append((idx, line))
                brace_depth += line.count("{") - line.count("}")
                if brace_depth <= 0:
                    in_function = False
                    self._check_access_control(
                        func_name, header_text, func_lines, source_code, file_path,
                        sensitive_keywords, auth_patterns, findings
                    )
                    func_lines = []

        return findings

    def _check_access_control(
        self,
        func_name: str,
        header_text: str,
        func_lines: List[tuple],
        source_code: str,
        file_path: str,
        sensitive_keywords: List[str],
        auth_patterns: List[str],
        findings: List[RawFinding]
    ):
        body_text = "\n".join([fl[1] for fl in func_lines])
        all_func_text = header_text + "\n" + body_text

        # Ignore internal / private functions
        is_public_or_external = (
            "public" in header_text or "external" in header_text or
            ("internal" not in header_text and "private" not in header_text)
        )
        if not is_public_or_external or "internal" in header_text or "private" in header_text:
            return

        # Check if function name matches sensitive operations
        lower_name = func_name.lower()
        is_sensitive = any(sk in lower_name for sk in sensitive_keywords)

        # Check for state changing actions like transfer, mint, selfdestruct, owner assignment
        has_owner_assignment = bool(re.search(r"\bowner\s*=\s*", body_text))
        has_transfer = bool(re.search(r"\.transfer\s*\(|\.call\{value:", body_text))

        if is_sensitive or has_owner_assignment:
            has_auth = any(re.search(ap, all_func_text, re.IGNORECASE) for ap in auth_patterns)
            if not has_auth:
                line_no = func_lines[0][0]
                snippet = self.extract_snippet(source_code, line_no, context_lines=3)
                severity = "CRITICAL" if ("owner" in lower_name or "destruct" in lower_name or "drain" in lower_name) else "HIGH"

                findings.append(RawFinding(
                    title=f"Missing Access Control on Sensitive Function '{func_name}'",
                    category="ACCESS_CONTROL",
                    severity=severity,
                    confidence="HIGH",
                    engine="custom",
                    description=(
                        f"Function '{func_name}' on line {line_no} is marked public/external and modifies privileged contract state "
                        f"or transfers assets, but lacks access control restrictions (such as 'onlyOwner' or OpenZeppelin AccessControl)."
                    ),
                    recommendation=(
                        f"Restrict access to '{func_name}' using OpenZeppelin's 'Ownable' modifier (onlyOwner) "
                        "or 'AccessControl' role validation."
                    ),
                    file_path=file_path,
                    line_start=line_no,
                    line_end=func_lines[-1][0],
                    code_snippet=snippet,
                    cwe_id="CWE-284",
                    swc_id="SWC-105",
                    cvss_score=8.6 if severity == "CRITICAL" else 7.8
                ))
