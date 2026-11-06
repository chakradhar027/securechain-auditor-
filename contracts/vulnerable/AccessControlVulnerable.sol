// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AccessControlVulnerable
 * @notice Demonstrates missing authorization and unsafe tx.origin usage.
 */
contract AccessControlVulnerable {
    address public owner;
    mapping(address => uint256) public balances;

    event OwnerChanged(address indexed previousOwner, address indexed newOwner);

    constructor() {
        owner = msg.sender;
    }

    // Vulnerability 1: Missing access control on sensitive ownership transfer
    function setOwner(address newOwner) external {
        require(newOwner != address(0), "Invalid address");
        emit OwnerChanged(owner, newOwner);
        owner = newOwner;
    }

    // Vulnerability 2: Unsafe tx.origin authorization
    function emergencyWithdraw(address payable recipient) external {
        require(tx.origin == owner, "Only owner can drain via tx.origin");
        recipient.transfer(address(this).balance);
    }

    // Vulnerability 3: Public selfdestruct without authorization
    function kill() external {
        selfdestruct(payable(owner));
    }

    receive() external payable {}
}

