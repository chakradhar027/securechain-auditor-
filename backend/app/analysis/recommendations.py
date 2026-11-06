import os
import re
from typing import Dict, Any, Optional

CATEGORY_RECOMMENDATIONS: Dict[str, Dict[str, str]] = {
    "REENTRANCY": {
        "summary": "Implement Checks-Effects-Interactions (CEI) & ReentrancyGuard",
        "action": (
            "1. Update internal state mappings (e.g. balances[msg.sender] = 0) BEFORE executing any external ether transfer or contract call.\n"
            "2. Inherit OpenZeppelin's ReentrancyGuard and apply 'nonReentrant' modifier to state-modifying external functions.\n"
            "3. Use pull-payment patterns rather than pushing funds automatically."
        ),
        "code_example": (
            "// Secure CEI Pattern\n"
            "function withdraw(uint256 amount) external nonReentrant {\n"
            "    require(balances[msg.sender] >= amount, \"Insufficient funds\");\n"
            "    balances[msg.sender] -= amount; // State effect first\n"
            "    (bool ok, ) = msg.sender.call{value: amount}(\"\"); // External interaction last\n"
            "    require(ok, \"Transfer failed\");\n"
            "}"
        )
    },
    "ACCESS_CONTROL": {
        "summary": "Enforce Role-Based Access Control and Validate Caller Identity",
        "action": (
            "1. Restrict privileged functions (mint, burn, withdraw, setOwner) with 'onlyOwner' or OpenZeppelin AccessControl.\n"
            "2. Never authenticate authorization checks via 'tx.origin'; strictly use 'msg.sender'.\n"
            "3. Completely eliminate obsolete 'selfdestruct' instructions."
        ),
        "code_example": (
            "// Secure Access Control\n"
            "import \"@openzeppelin/contracts/access/Ownable2Step.sol\";\n\n"
            "contract SecureVault is Ownable2Step {\n"
            "    constructor() Ownable(msg.sender) {}\n\n"
            "    function emergencyWithdraw() external onlyOwner {\n"
            "        // Only confirmed owner can invoke\n"
            "    }\n"
            "}"
        )
    },
    "UNCHECKED_CALL": {
        "summary": "Check Return Values & Adopt SafeERC20",
        "action": (
            "1. Always unpack boolean success flags from low-level calls: (bool ok, ) = target.call(...); require(ok, 'Call failed');\n"
            "2. Replace naked .transfer() and .send() with explicit .call{value: ...} and error bubbling.\n"
            "3. For ERC-20 tokens, wrap token interactions with OpenZeppelin's 'SafeERC20' library."
        ),
        "code_example": (
            "// Safe ERC-20 & Low-Level Calls\n"
            "using SafeERC20 for IERC20;\n\n"
            "function safePayout(IERC20 token, address to, uint256 amt) external {\n"
            "    token.safeTransfer(to, amt); // Handles missing returns and false booleans safely\n"
            "}"
        )
    },
    "ORACLE_MANIPULATION": {
        "summary": "Decentralized Price Oracles & Multi-Block TWAPs",
        "action": (
            "1. Never derive pricing from raw pool reserves (reserve0 / reserve1) or instantaneous spot token balances.\n"
            "2. Integrate decentralized oracle feeds such as Chainlink AggregatorV3Interface.\n"
            "3. Verify price freshness: check answeredInRound >= roundId, updatedAt > 0, and price > 0."
        ),
        "code_example": (
            "// Chainlink Price Feed Validation\n"
            "(uint80 roundId, int256 price, , uint256 updatedAt, uint80 answeredInRound) = priceFeed.latestRoundData();\n"
            "require(price > 0, \"Negative or zero price\");\n"
            "require(updatedAt != 0 && block.timestamp - updatedAt < 3600, \"Stale price feed\");\n"
            "require(answeredInRound >= roundId, \"Stale round\");"
        )
    }
}

def inspect_call_safety(source_code: str, line_no: Optional[int] = None, code_snippet: str = "") -> Dict[str, Any]:
    """
    Inspects low-level call usage in source code to determine:
    1. Whether the return boolean value is captured and verified.
    2. Whether reentrancy protections (Checks-Effects-Interactions and/or nonReentrant mutex) are in place.
    """
    if not source_code:
        return {"return_checked": False, "reentrancy_protected": False, "is_safe": False}

    lines = source_code.splitlines()
    target_idx = None
    if line_no and 1 <= line_no <= len(lines):
        target_idx = line_no - 1
    else:
        for idx, line in enumerate(lines):
            if ".call{" in line or ".call(" in line or ".send(" in line:
                target_idx = idx
                break

    if target_idx is None:
        return {"return_checked": False, "reentrancy_protected": False, "is_safe": False}

    call_line = lines[target_idx]

    # Find the enclosing function boundaries
    fn_start = 0
    fn_end = len(lines)
    if target_idx is not None:
        for i in range(target_idx, -1, -1):
            if re.search(r"\bfunction\b", lines[i]):
                fn_start = i
                break
        for i in range(target_idx, len(lines)):
            if lines[i].strip() == "}":
                fn_end = i + 1
                break

    # Locate the actual call or send statement within function scope (or whole code)
    call_idx = None
    search_range = range(fn_start, fn_end) if target_idx is not None else range(len(lines))
    for i in search_range:
        l = lines[i]
        if ".call{" in l or ".call(" in l or re.search(r"\.send\s*\(", l):
            call_idx = i
            break

    if call_idx is None:
        # Search anywhere in source code as fallback
        for i in range(len(lines)):
            l = lines[i]
            if ".call{" in l or ".call(" in l or re.search(r"\.send\s*\(", l):
                call_idx = i
                for j in range(call_idx, -1, -1):
                    if re.search(r"\bfunction\b", lines[j]):
                        fn_start = j
                        break
                for j in range(call_idx, len(lines)):
                    if lines[j].strip() == "}":
                        fn_end = j + 1
                        break
                break

    if call_idx is None:
        return {"return_checked": False, "reentrancy_protected": False, "is_safe": False}

    call_line = lines[call_idx]
    scope_lines = lines[fn_start:fn_end]
    scope_text = "\n".join(scope_lines)

    # 1. Check return value verification
    return_checked = False
    if re.search(r"require\s*\([^;]*\.(?:call|send)\s*\(", call_line):
        return_checked = True
    else:
        # Check boolean unpack pattern: (bool success, ) = ... or bool success = ... or (success, ...) = ...
        bool_match = (
            re.search(r"\(\s*bool\s+([a-zA-Z0-9_]+)\s*,", call_line) or
            re.search(r"\bbool\s+([a-zA-Z0-9_]+)\s*=", call_line) or
            re.search(r"\(\s*([a-zA-Z0-9_]+)\s*,\s*(?:bytes\s+memory\s+[a-zA-Z0-9_]+|None)?\s*\)\s*=", call_line)
        )
        if bool_match:
            var_name = bool_match.group(1)
            for l in lines[call_idx:fn_end]:
                if (
                    re.search(rf"\brequire\s*\(\s*{re.escape(var_name)}\b", l) or
                    re.search(rf"\bif\s*\(\s*!{re.escape(var_name)}\b", l) or
                    re.search(rf"\bassert\s*\(\s*{re.escape(var_name)}\b", l)
                ):
                    return_checked = True
                    break

    # 2. Check reentrancy protections
    reentrancy_protected = False
    # Check for nonReentrant modifier in function signature or scope
    if "nonReentrant" in scope_text:
        reentrancy_protected = True
    elif "ReentrancyGuard" in source_code:
        fn_header = " ".join(lines[fn_start:min(call_idx + 1, fn_start + 4)])
        if "nonReentrant" in fn_header:
            reentrancy_protected = True

    # Check for CEI (state balances updated before call)
    state_updated_before_call = False
    for l in lines[fn_start:call_idx]:
        stripped = l.strip()
        if re.search(r"\b(balances|rewards|shares|deposits|userBalances)\s*\[[^\]]+\]\s*(-=|=)", stripped):
            state_updated_before_call = True
            break

    if state_updated_before_call:
        reentrancy_protected = True

    is_safe = return_checked and reentrancy_protected
    return {
        "return_checked": return_checked,
        "reentrancy_protected": reentrancy_protected,
        "is_safe": is_safe
    }

def get_recommendation_for_finding(
    category_or_finding: Any,
    default_recommendation_or_source: str = "",
    source_code: str = ""
) -> str:
    """
    Returns an actionable, context-aware remediation recommendation for a finding.
    Supports either:
      - get_recommendation_for_finding(finding_dict, source_code=source_code)
      - get_recommendation_for_finding(category_str, default_recommendation_str)
    """
    if isinstance(category_or_finding, dict):
        finding = category_or_finding
        src = source_code or (default_recommendation_or_source if len(default_recommendation_or_source) > 100 else "")
        severity = finding.get("severity", "MEDIUM").upper()
        title = finding.get("title", "")
        title_lower = title.lower()
        category = finding.get("category", "OTHER").upper()
        existing_rec = finding.get("recommendation", "")

        # 1. Informational findings
        if severity == "INFORMATIONAL":
            if "low level call" in title_lower or "low-level-call" in title_lower:
                safety = inspect_call_safety(src, finding.get("line_start"), finding.get("code_snippet", ""))
                if safety["is_safe"]:
                    return (
                        "Informational Advisory: Low-level call implementation verified. Return value is explicitly "
                        "checked via require() and reentrancy protection (nonReentrant modifier and Checks-Effects-Interactions) "
                        "is actively enforced. If direct low-level invocation is intentional for native ether transfer, no code "
                        "changes are required. For enhanced architectural abstraction, consider wrapping external transfers "
                        "with OpenZeppelin's Address.sendValue or implementing pull-payment withdrawals."
                    )
                elif safety["return_checked"]:
                    return (
                        "Advisory: Return value of low-level call is validated. Ensure strict Checks-Effects-Interactions (CEI) "
                        "ordering or apply OpenZeppelin's 'nonReentrant' modifier to safeguard all external call paths."
                    )
                else:
                    return (
                        "Advisory: Low-level call return value should be validated: capture boolean status and verify with "
                        "require(success, 'Call failed'); or adopt OpenZeppelin Address.sendValue."
                    )

            if "solc version" in title_lower or "pragma" in title_lower:
                return (
                    "Lock the pragma compiler version to a specific, production-tested version (e.g. 'pragma solidity 0.8.20;') "
                    "instead of using floating ranges ('^0.8.20') to guarantee deterministic bytecode generation."
                )

            if "naming convention" in title_lower:
                return "Advisory: Follow standard Solidity naming conventions (CapWords for contracts/structs/events, mixedCase for functions/variables)."

            if "immutable" in title_lower:
                return "Optimization Advisory: State variables initialized only once in the constructor should be marked 'immutable' to reduce runtime gas usage."

            if existing_rec and not any(generic in existing_rec for generic in ["Review Slither documentation", "Review and remediate"]):
                return existing_rec

            return "Informational Code Advisory: Review referenced code for adherence to smart contract best practices. This advisory notice does not represent an exploitable vulnerability."

        # 2. Unchecked call findings (active vulnerabilities)
        if category == "UNCHECKED_CALL" or "unchecked" in title_lower:
            snippet = finding.get("code_snippet", "") or ""
            if "send" in title_lower or ".send(" in snippet:
                return (
                    "Avoid deprecated '.send()'. Use low-level '.call{value: ...}(\"\")' with require() error handling or OpenZeppelin's Address.sendValue:\n"
                    "(bool success, ) = recipient.call{value: amount}(\"\");\n"
                    "require(success, \"Send failed\");"
                )
            if "erc-20" in title_lower or "token" in title_lower:
                return (
                    "Wrap ERC-20 token interactions with OpenZeppelin SafeERC20 library ('safeTransfer' / 'safeTransferFrom') "
                    "to handle missing return values and tokens that return false on failure."
                )
            safety = inspect_call_safety(src, finding.get("line_start"), snippet)
            if safety["is_safe"]:
                return (
                    "Low-level call verified safe: Return boolean is captured and checked with require(), and reentrancy protections are active. "
                    "If intentional, no further modification required."
                )
            elif not safety["return_checked"]:
                return (
                    "Capture and verify the return status of low-level call:\n"
                    "(bool success, ) = target.call{value: ...}(\"\");\n"
                    "require(success, \"Low-level call failed\");\n"
                    "Ensure state variables are updated before the call (CEI) to prevent reentrancy."
                )
            elif not safety["reentrancy_protected"]:
                return (
                    "Return value is verified, but reentrancy protection is absent. Update contract state balances before dispatching "
                    "the external call (CEI) and attach OpenZeppelin's nonReentrant modifier."
                )

        # 3. Standard category recommendations for active issues
        info = CATEGORY_RECOMMENDATIONS.get(category)
        if info:
            return f"{info['summary']}\n\nActions:\n{info['action']}"

        return existing_rec or "Review and remediate highlighted code according to smart contract security best practices."

    # Legacy string-based signature: (category_str, default_recommendation_str)
    category_str = str(category_or_finding).upper()
    info = CATEGORY_RECOMMENDATIONS.get(category_str)
    if info:
        return f"{info['summary']}\n\nActions:\n{info['action']}"
    return default_recommendation_or_source
