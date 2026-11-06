// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SWC106_UnprotectedSelfdestruct_Fixed
 * @notice Fixed SWC-106: selfdestruct completely eliminated or restricted behind multi-step governance.
 */
contract SWC106_UnprotectedSelfdestruct_Fixed {
    address public immutable owner;
    bool public isPaused;

    event EmergencyPaused(address indexed caller);

    modifier onlyOwner() {
        require(msg.sender == owner, "Caller not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {}

    // Fixed: Emergency pause mechanism replacing dangerous irreversible selfdestruct
    function emergencyPause() external onlyOwner {
        isPaused = true;
        emit EmergencyPaused(msg.sender);
    }

    // Emergency withdrawal to prevent locked ether
    function emergencyWithdraw(address payable recipient) external onlyOwner {
        require(recipient != address(0), "Invalid recipient");
        recipient.transfer(address(this).balance);
    }
}
