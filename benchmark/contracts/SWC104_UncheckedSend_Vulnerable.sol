// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SWC104_UncheckedSend_Vulnerable
 * @notice Canonical SWC-104 Unchecked Call Return Value.
 * Failure to verify the return value of send causes silent state inconsistency.
 */
contract SWC104_UncheckedSend_Vulnerable {
    mapping(address => uint256) public userBalance;

    function deposit() external payable {
        userBalance[msg.sender] += msg.value;
    }

    // Vulnerable: Return value of send ignored
    function withdrawSilent(address payable to) external {
        uint256 amount = userBalance[msg.sender];
        require(amount > 0, "Zero balance");
        userBalance[msg.sender] = 0;
        to.send(amount); // Return value ignored
    }
}

