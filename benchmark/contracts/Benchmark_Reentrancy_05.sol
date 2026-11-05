// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Benchmark_Reentrancy_05 {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        // Reentrancy vulnerable call before state update variant 5
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
        balances[msg.sender] = 0;
        totalDeposits -= amount;
    }
}
