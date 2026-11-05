import os
import json

BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
CONTRACTS_DIR = os.path.join(BENCHMARK_DIR, "contracts")
EXPECTED_DIR = os.path.join(BENCHMARK_DIR, "expected_findings")
os.makedirs(CONTRACTS_DIR, exist_ok=True)
os.makedirs(EXPECTED_DIR, exist_ok=True)

# Templates for 50+ benchmark test cases
# 1. Reentrancy variants (15 contracts)
# 2. Access control variants (15 contracts)
# 3. Unchecked call variants (10 contracts)
# 4. Oracle manipulation variants (10 contracts)
# 5. Secure baseline contracts (10 contracts)

contracts_data = []

# Reentrancy group
for i in range(1, 16):
    name = f"Benchmark_Reentrancy_{i:02d}"
    code = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract {name} {{
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    function deposit() external payable {{
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }}

    function withdraw() external {{
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        // Reentrancy vulnerable call before state update variant {i}
        (bool ok, ) = msg.sender.call{{value: amount}}("");
        require(ok, "Transfer failed");
        balances[msg.sender] = 0;
        totalDeposits -= amount;
    }}
}}
"""
    contracts_data.append({
        "name": name,
        "category": "REENTRANCY",
        "has_vulnerability": True,
        "expected_severity": "CRITICAL",
        "code": code
    })

# Access Control group
for i in range(1, 16):
    name = f"Benchmark_AccessControl_{i:02d}"
    tx_origin_clause = "require(tx.origin == admin, 'Not admin');" if i % 2 == 0 else ""
    code = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract {name} {{
    address public admin;
    bool public isPaused;

    constructor() {{
        admin = msg.sender;
    }}

    // Missing access control on sensitive function variant {i}
    function setAdmin(address newAdmin) external {{
        {tx_origin_clause}
        admin = newAdmin;
    }}

    function emergencyDrain(address payable recipient) external {{
        {tx_origin_clause}
        recipient.transfer(address(this).balance);
    }}
}}
"""
    contracts_data.append({
        "name": name,
        "category": "ACCESS_CONTROL",
        "has_vulnerability": True,
        "expected_severity": "CRITICAL" if not tx_origin_clause else "HIGH",
        "code": code
    })

# Unchecked calls group
for i in range(1, 11):
    name = f"Benchmark_UncheckedCall_{i:02d}"
    code = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract {name} {{
    mapping(address => uint256) public shares;

    function distribute(address payable recipient, uint256 amt) external {{
        shares[recipient] = 0;
        // Unchecked low-level send variant {i}
        recipient.send(amt);
    }}

    function executeRaw(address target, bytes calldata data) external {{
        // Unchecked low level call
        target.call(data);
    }}
}}
"""
    contracts_data.append({
        "name": name,
        "category": "UNCHECKED_CALL",
        "has_vulnerability": True,
        "expected_severity": "HIGH",
        "code": code
    })

# Oracle manipulation group
for i in range(1, 11):
    name = f"Benchmark_Oracle_{i:02d}"
    code = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV2Pair {{
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}}

contract {name} {{
    IUniswapV2Pair public pair;

    constructor(address _pair) {{
        pair = IUniswapV2Pair(_pair);
    }}

    // Vulnerable spot oracle calculation variant {i}
    function queryPrice() external view returns (uint256) {{
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        return (uint256(r0) * 1e18) / uint256(r1);
    }}
}}
"""
    contracts_data.append({
        "name": name,
        "category": "ORACLE_MANIPULATION",
        "has_vulnerability": True,
        "expected_severity": "CRITICAL",
        "code": code
    })

# Secure baseline contracts group
for i in range(1, 11):
    name = f"Benchmark_Secure_{i:02d}"
    code = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract ReentrancyGuard {{
    uint256 private _status = 1;
    modifier nonReentrant() {{
        require(_status != 2, "Reentrant");
        _status = 2;
        _;
        _status = 1;
    }}
}}

contract {name} is ReentrancyGuard {{
    address public owner;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {{
        require(msg.sender == owner, "Unauthorized");
        _;
    }}

    constructor() {{
        owner = msg.sender;
    }}

    function deposit() external payable {{
        require(msg.value > 0, "Zero deposit");
        balances[msg.sender] += msg.value;
    }}

    function withdraw() external nonReentrant {{
        uint256 amt = balances[msg.sender];
        require(amt > 0, "Zero balance");
        balances[msg.sender] = 0; // State effect before call
        (bool ok, ) = msg.sender.call{{value: amt}}("");
        require(ok, "Transfer failed");
    }}

    function setOwner(address newOwner) external onlyOwner {{
        require(newOwner != address(0), "Invalid");
        owner = newOwner;
    }}
}}
"""
    contracts_data.append({
        "name": name,
        "category": "SECURE",
        "has_vulnerability": False,
        "expected_severity": "SECURE",
        "code": code
    })

# Write files and ground truth JSON
ground_truth = {}
for item in contracts_data:
    file_path = os.path.join(CONTRACTS_DIR, f"{item['name']}.sol")
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(item["code"])

    ground_truth[item["name"]] = {
        "filename": f"{item['name']}.sol",
        "category": item["category"],
        "has_vulnerability": item["has_vulnerability"],
        "expected_severity": item["expected_severity"]
    }

ground_truth_path = os.path.join(EXPECTED_DIR, "benchmark_ground_truth.json")
with open(ground_truth_path, "w", encoding="utf-8") as f:
    json.dump(ground_truth, f, indent=2)

print(f"Generated {len(contracts_data)} benchmark contracts and ground truth catalog at {ground_truth_path}")
