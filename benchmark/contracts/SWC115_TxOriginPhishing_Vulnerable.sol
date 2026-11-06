// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SWC115_TxOriginPhishing_Vulnerable
 * @notice Canonical SWC-115 Authorization via tx.origin.
 * Vulnerable to phishing attacks when owner interacts with malicious intermediary contract.
 */
contract SWC115_TxOriginPhishing_Vulnerable {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {}

    // Vulnerable: tx.origin authorization allows phishing attacks
    function transferTo(address payable dest, uint256 amount) external {
        require(tx.origin == owner, "Caller not authorized");
        require(address(this).balance >= amount, "Insufficient balance");
        dest.transfer(amount);
    }
}

