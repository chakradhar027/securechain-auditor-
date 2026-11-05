import pytest
from app.scanners.scanner_manager import ScannerManager

VULN_CODE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TestVault {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() { owner = msg.sender; }

    function withdraw() public {
        uint256 amt = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amt}("");
        balances[msg.sender] = 0;
    }

    function kill() public {
        selfdestruct(payable(owner));
    }
}
"""

@pytest.mark.asyncio
async def test_scanner_manager_pipeline():
    manager = ScannerManager()
    findings, fuzz_meta = await manager.run_scanners(
        file_path="contracts/vulnerable/TestVault.sol",
        source_code=VULN_CODE,
        enabled_engines=["custom", "slither", "mythril", "foundry"]
    )

    assert len(findings) > 0
    assert fuzz_meta["total"] > 0
    # Custom, Slither, Mythril, Foundry findings present
    engines_found = {f.engine for f in findings}
    assert "custom" in engines_found
