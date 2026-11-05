// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract ReentrancyGuard {
    uint256 private _status = 1;
    modifier nonReentrant() {
        require(_status != 2, "Reentrant");
        _status = 2;
        _;
        _status = 1;
    }
}

contract Benchmark_Secure_04 is ReentrancyGuard {
    address public owner;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner, "Unauthorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        require(msg.value > 0, "Zero deposit");
        balances[msg.sender] += msg.value;
    }

    function withdraw() external nonReentrant {
        uint256 amt = balances[msg.sender];
        require(amt > 0, "Zero balance");
        balances[msg.sender] = 0; // State effect before call
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "Transfer failed");
    }

    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid");
        owner = newOwner;
    }
}
