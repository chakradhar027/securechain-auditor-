from typing import Dict

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

def get_recommendation_for_finding(category: str, default_recommendation: str) -> str:
    cat = category.upper()
    info = CATEGORY_RECOMMENDATIONS.get(cat)
    if info:
        return f"{info['summary']}\n\nActions:\n{info['action']}"
    return default_recommendation
