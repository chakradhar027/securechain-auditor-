// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ReentrancyFixed
 * @notice Fixed contract adopting Checks-Effects-Interactions (CEI) and ReentrancyGuard mutex.
 */
abstract contract ReentrancyGuard {
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
}

contract ReentrancyFixed is ReentrancyGuard {
    mapping(address => uint256) public balances;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    function deposit() external payable {
        require(msg.value > 0, "Zero deposit");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw() external nonReentrant {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance to withdraw");

        // 1. Effects: State update BEFORE external call
        balances[msg.sender] = 0;

        // 2. Interaction: External call after state zeroed
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "ETH transfer failed");

        emit Withdrawn(msg.sender, balance);
    }

    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

