// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SWC105_UnprotectedWithdraw_Vulnerable
 * @notice Canonical SWC-105 Unprotected Ether Withdrawal.
 * Missing access control modifier allows any caller to drain contract balance.
 */
contract SWC105_UnprotectedWithdraw_Vulnerable {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {}

    // Vulnerable: Anyone can call withdrawAll and drain contract funds
    function withdrawAll(address payable recipient) external {
        require(recipient != address(0), "Invalid recipient");
        recipient.transfer(address(this).balance);
    }

    // Vulnerable: Unprotected ownership change
    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}

