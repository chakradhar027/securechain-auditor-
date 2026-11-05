import pytest
from app.detectors.reentrancy import ReentrancyDetector
from app.detectors.access_control import AccessControlDetector
from app.detectors.unchecked_calls import UncheckedCallsDetector
from app.detectors.oracle_manipulation import OracleManipulationDetector

VULNERABLE_REENTRANCY_CODE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract EtherStore {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 bal = balances[msg.sender];
        require(bal > 0);
        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send Ether");
        balances[msg.sender] = 0;
    }
}
"""

VULNERABLE_ACCESS_CONTROL_CODE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BankVault {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    function withdrawAll() public {
        payable(msg.sender).transfer(address(this).balance);
    }
}
"""

VULNERABLE_UNCHECKED_CALL_CODE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UncheckedCaller {
    function payout(address payable recipient, uint256 amount) public {
        recipient.send(amount);
    }

    function trigger(address target) public {
        target.call(abi.encodeWithSignature("ping()"));
    }
}
"""

VULNERABLE_ORACLE_CODE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

contract LendingPool {
    IUniswapV2Pair public pool;

    function getCollateralPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1, ) = pool.getReserves();
        return (uint256(reserve0) * 1e18) / uint256(reserve1);
    }
}
"""

def test_reentrancy_detector():
    detector = ReentrancyDetector()
    findings = detector.detect(VULNERABLE_REENTRANCY_CODE)
    assert len(findings) > 0
    assert any(f.category == "REENTRANCY" for f in findings)
    assert any(f.severity in ["CRITICAL", "HIGH"] for f in findings)

def test_access_control_detector():
    detector = AccessControlDetector()
    findings = detector.detect(VULNERABLE_ACCESS_CONTROL_CODE)
    assert len(findings) > 0
    assert any(f.category == "ACCESS_CONTROL" for f in findings)
    assert any("setOwner" in f.title or "withdrawAll" in f.title for f in findings)

def test_unchecked_calls_detector():
    detector = UncheckedCallsDetector()
    findings = detector.detect(VULNERABLE_UNCHECKED_CALL_CODE)
    assert len(findings) >= 2
    assert any("send" in f.title.lower() for f in findings)
    assert any("call" in f.title.lower() for f in findings)

def test_oracle_manipulation_detector():
    detector = OracleManipulationDetector()
    findings = detector.detect(VULNERABLE_ORACLE_CODE)
    assert len(findings) > 0
    assert any(f.category == "ORACLE_MANIPULATION" for f in findings)
    assert any(f.severity == "CRITICAL" for f in findings)
