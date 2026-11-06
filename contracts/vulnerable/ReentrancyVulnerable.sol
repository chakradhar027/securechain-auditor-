// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ReentrancyVulnerable
 * @notice Classical vulnerable ether vault violating Checks-Effects-Interactions (CEI).
 */
contract ReentrancyVulnerable {
    mapping(address => uint256) public balances;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    function deposit() external payable {
        require(msg.value > 0, "Zero deposit");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance to withdraw");

        // Vulnerability: External call before state update
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "ETH transfer failed");

        // State update happens AFTER external call
        balances[msg.sender] = 0;
        emit Withdrawn(msg.sender, balance);
    }

    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

