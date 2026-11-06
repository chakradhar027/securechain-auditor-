// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SWC106_UnprotectedSelfdestruct_Vulnerable
 * @notice Canonical SWC-106 Unprotected selfdestruct Instruction.
 * Allows any attacker to permanently destroy the contract and claim residual ether.
 */
contract SWC106_UnprotectedSelfdestruct_Vulnerable {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {}

    // Vulnerable: Missing access control on selfdestruct
    function kill() external {
        selfdestruct(payable(msg.sender));
    }
}

