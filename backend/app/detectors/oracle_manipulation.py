import re
from typing import List
from app.detectors.base_detector import BaseDetector, RawFinding

class OracleManipulationDetector(BaseDetector):
    def __init__(self):
        super().__init__("OracleManipulationDetector")

    def detect(self, source_code: str, file_path: str = "") -> List[RawFinding]:
        findings: List[RawFinding] = []
        lines = source_code.splitlines()

        # AMM spot reserve calculation patterns: e.g. reserve0 / reserve1, or getReserves()
        uses_reserves = bool(re.search(r"\bgetReserves\s*\(", source_code))
        uses_balance_for_price = bool(
            re.search(r"balanceOf\s*\([^)]*\)\s*[/|\*]", source_code) or
            re.search(r"address\(this\)\.balance\s*[/|\*]", source_code)
        )
        has_twap = bool(re.search(r"\bTWAP\b|\bconsult\b|\bobserve\b|\bperiodSize\b", source_code, re.IGNORECASE))
        has_chainlink = bool(re.search(r"AggregatorV3Interface|latestRoundData", source_code))

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue

            # Spot AMM reserve pricing
            if uses_reserves and not has_twap:
                if re.search(r"\breserve[0-1]\s*[/|\*]\s*reserve[0-1]", line) or re.search(r"getReserves\s*\(", line):
                    snippet = self.extract_snippet(source_code, idx, context_lines=3)
                    findings.append(RawFinding(
                        title="Vulnerable Spot AMM Oracle (Flash Loan Manipulation Risk)",
                        category="ORACLE_MANIPULATION",
                        severity="CRITICAL",
                        confidence="HIGH",
                        engine="custom",
                        description=(
                            f"Line {idx} derives price calculations directly from immediate spot pool reserves or getReserves(): '{stripped}'. "
                            "Spot balances and reserves can be skewed within a single transaction using atomic flash loans, "
                            "allowing an attacker to borrow millions, distort the exchange rate, execute a swap/borrow at artificial prices, "
                            "and repay the flash loan with massive profit."
                        ),
                        recommendation=(
                            "Do not use spot DEX reserves for asset valuation. Implement Uniswap v3 TWAP (Time-Weighted Average Price) "
                            "with a multi-block observation window or integrate decentralized oracles such as Chainlink Price Feeds."
                        ),
                        file_path=file_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=snippet,
                        cwe_id="CWE-682",
                        swc_id="SWC-133",
                        cvss_score=9.3
                    ))
                    break # One primary finding per contract is sufficient for reserve calculation

            # Instantaneous balance of contract used for exchange calculation
            if uses_balance_for_price and not has_twap and not has_chainlink:
                if re.search(r"balanceOf\s*\(", line) or "address(this).balance" in line:
                    snippet = self.extract_snippet(source_code, idx, context_lines=2)
                    findings.append(RawFinding(
                        title="Spot Balance Used for Rate/Pricing Calculation",
                        category="ORACLE_MANIPULATION",
                        severity="HIGH",
                        confidence="MEDIUM",
                        engine="custom",
                        description=(
                            f"Line {idx} calculates rates or collateral values using live token/ETH balances: '{stripped}'. "
                            "Direct token balance inquiries can be manipulated via flash loans or unsolicited token transfers (donation attacks)."
                        ),
                        recommendation="Track internal accounting balances rather than querying raw balanceOf(address(this)) or pool balances directly.",
                        file_path=file_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=snippet,
                        cwe_id="CWE-682",
                        swc_id="SWC-133",
                        cvss_score=8.1
                    ))
                    break

            # Chainlink Stale Price / Missing Validation Check
            if "latestRoundData" in line:
                # Look ahead for checks on answeredInRound, updatedAt, or price > 0
                ahead_text = "\n".join(lines[idx:min(len(lines), idx + 10)])
                has_stale_check = (
                    ("updatedAt" in ahead_text and "require" in ahead_text) or
                    ("answeredInRound" in ahead_text) or
                    ("block.timestamp" in ahead_text)
                )
                if not has_stale_check:
                    snippet = self.extract_snippet(source_code, idx, context_lines=3)
                    findings.append(RawFinding(
                        title="Missing Chainlink Stale Price & Round Validation",
                        category="ORACLE_MANIPULATION",
                        severity="MEDIUM",
                        confidence="HIGH",
                        engine="custom",
                        description=(
                            f"Line {idx} calls Chainlink's 'latestRoundData' without validating whether the fetched price is fresh: '{stripped}'. "
                            "If the oracle feed stops updating or falls behind, the protocol may trade on stale, frozen market prices."
                        ),
                        recommendation=(
                            "Verify round freshness: 'require(updatedAt != 0 && block.timestamp - updatedAt < MAX_TIMEOUT, \"Stale price\");' "
                            "and ensure 'price > 0'."
                        ),
                        file_path=file_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=snippet,
                        cwe_id="CWE-682",
                        swc_id="SWC-133",
                        cvss_score=5.9
                    ))

        return findings
