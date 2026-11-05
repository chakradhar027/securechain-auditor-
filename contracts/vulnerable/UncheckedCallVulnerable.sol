// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title UncheckedCallVulnerable
 * @notice Demonstrates unhandled return values from low-level calls and send.
 */
contract UncheckedCallVulnerable {
    mapping(address => uint256) public rewards;

    function addReward(address user) external payable {
        rewards[user] += msg.value;
    }

    // Vulnerability 1: Ignored return value of send
    function payReward(address payable recipient) external {
        uint256 amount = rewards[recipient];
        rewards[recipient] = 0;
        // Silent failure if recipient reverts or uses >2300 gas
        recipient.send(amount);
    }

    // Vulnerability 2: Ignored return value of low-level call
    function forwardCall(address target, bytes calldata data) external {
        // Return boolean not captured or checked
        target.call(data);
    }
}
