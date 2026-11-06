import re
from typing import List
from app.detectors.base_detector import BaseDetector, RawFinding

class ReentrancyDetector(BaseDetector):
    def __init__(self):
        super().__init__("ReentrancyDetector")

    def detect(self, source_code: str, file_path: str = "") -> List[RawFinding]:
        findings: List[RawFinding] = []
        lines = source_code.splitlines()

        # Regular expressions for external calls that transfer ETH/tokens or control flow
        call_patterns = [
            (r"\.call\{value:\s*[^}]+\}\s*\([^)]*\)", "call{value: ...}"),
            (r"\.call\.value\s*\([^)]*\)\s*\([^)]*\)", "call.value(...)"),
            (r"\bmsg\.sender\.call\b", "msg.sender.call"),
            (r"\.transfer\s*\([^)]+\)", "transfer(...)"),
            (r"\.send\s*\([^)]+\)", "send(...)"),
        ]

        # State mutation patterns
        state_write_patterns = [
            r"\b[a-zA-Z0-9_]+\[[^\]]+\]\s*(-=|\+=|=)", # balances[msg.sender] = 0
            r"\b[a-zA-Z0-9_]+\s*(-=|\+=|=)\s*[^;]+;",
            r"\bdelete\s+[a-zA-Z0-9_]+\[[^\]]+\]",
        ]

        # Check function boundaries
        func_regex = re.compile(r"function\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)[^{]*\{")
        
        in_function = False
        func_name = ""
        func_start_line = 0
        func_lines = []
        brace_depth = 0

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Ignore comments
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue

            match = func_regex.search(line)
            if match and not in_function:
                in_function = True
                func_name = match.group(1)
                func_start_line = idx
                func_lines = [(idx, line)]
                brace_depth = line.count("{") - line.count("}")
                continue

            if in_function:
                func_lines.append((idx, line))
                brace_depth += line.count("{") - line.count("}")
                if brace_depth <= 0:
                    # End of function, analyze its body
                    in_function = False
                    f_res = self._analyze_function(func_name, func_lines, source_code, file_path)
                    findings.extend(f_res)
                    func_lines = []

        return findings

    def _analyze_function(self, func_name: str, func_lines: List[tuple], source_code: str, file_path: str) -> List[RawFinding]:
        findings = []
        func_text = "\n".join([fl[1] for fl in func_lines])

        has_reentrancy_guard = bool(
            re.search(r"\bnonReentrant\b", func_text, re.IGNORECASE) or 
            re.search(r"\block\b", func_text, re.IGNORECASE) or
            re.search(r"\bReentrancyGuard\b", source_code)
        )

        has_access_control = bool(
            re.search(r"\bonlyOwner\b|\bonlyAdmin\b|\bonlyRole\b|require\(msg\.sender\s*==", func_text)
        )

        external_call_lines = []
        state_write_lines = []

        for line_no, text in func_lines:
            stripped = text.strip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue

            # Check for external call
            is_call = False
            if (".call{" in text or ".call.value" in text or "msg.sender.call" in text or 
                (".transfer(" in text and "require(" not in text) or ".send(" in text):
                external_call_lines.append((line_no, text))
                is_call = True

            # Check for state modification
            if not is_call:
                if re.search(r"\b[a-zA-Z0-9_]+\[[^\]]+\]\s*(-=|\+=|=)", text) or re.search(r"\bdelete\s+", text):
                    state_write_lines.append((line_no, text))

        # Check Checks-Effects-Interactions (CEI) violation: external call happens BEFORE state modification
        for call_line, call_txt in external_call_lines:
            subsequent_writes = [sw for sw in state_write_lines if sw[0] > call_line]
            if subsequent_writes:
                sw_line, sw_txt = subsequent_writes[0]
                snippet = self.extract_snippet(source_code, call_line, context_lines=4)
                severity = "CRITICAL" if not has_reentrancy_guard else "HIGH"
                confidence = "HIGH" if not has_reentrancy_guard else "MEDIUM"

                findings.append(RawFinding(
                    title=f"Potential Reentrancy Vulnerability in '{func_name}'",
                    category="REENTRANCY",
                    severity=severity,
                    confidence=confidence,
                    engine="custom",
                    description=(
                        f"In function '{func_name}', an external call is executed on line {call_line} "
                        f"before the contract state is updated on line {sw_line} ('{sw_txt.strip()}'). "
                        f"An attacker can hijack control flow via a fallback/receive function to recursively "
                        f"drain funds or corrupt state before balance deductions occur. "
                        f"Exploitability Assessment: High Exploitability (Checks-Effects-Interactions violation)."
                    ),
                    recommendation=(
                        "Follow the Checks-Effects-Interactions (CEI) pattern: update all state variables (e.g. zero balance) "
                        "BEFORE making external calls. Alternatively, apply OpenZeppelin's ReentrancyGuard 'nonReentrant' modifier."
                    ),
                    file_path=file_path,
                    line_start=call_line,
                    line_end=sw_line,
                    code_snippet=snippet,
                    cwe_id="CWE-841",
                    swc_id="SWC-107",
                    cvss_score=8.9 if severity == "CRITICAL" else 7.5
                ))
            elif not has_reentrancy_guard and (".call{" in call_txt or "call.value" in call_txt):
                # If there are NO subsequent writes in this function:
                # 1. If restricted by access control (e.g. onlyOwner), it's an authorized administrative transfer.
                if has_access_control:
                    continue

                # 2. If state was updated BEFORE the call (Checks-Effects-Interactions pattern), it is not reentrant.
                has_prior_write = bool([sw for sw in state_write_lines if sw[0] < call_line])
                if has_prior_write:
                    continue

                # Public/unprotected low-level call without guard and without state accounting:
                snippet = self.extract_snippet(source_code, call_line, context_lines=3)
                findings.append(RawFinding(
                    title=f"Unprotected External Call Pattern in '{func_name}'",
                    category="REENTRANCY",
                    severity="LOW",
                    confidence="LOW",
                    engine="custom",
                    description=(
                        f"Function '{func_name}' executes a low-level call on line {call_line} without a 'nonReentrant' modifier. "
                        f"Exploitability Assessment: Low Risk. No subsequent state modification occurs in this function, "
                        f"but developers should ensure cross-function state cannot be manipulated by untrusted callbacks."
                    ),
                    recommendation="If cross-function state dependencies exist, inherit OpenZeppelin's ReentrancyGuard and apply 'nonReentrant'.",
                    file_path=file_path,
                    line_start=call_line,
                    line_end=call_line,
                    code_snippet=snippet,
                    cwe_id="CWE-841",
                    swc_id="SWC-107",
                    cvss_score=3.5
                ))

        return findings

