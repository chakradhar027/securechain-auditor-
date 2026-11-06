// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract ReentrancyGuard {
    uint256 private _status = 1;
    modifier nonReentrant() {
        require(_status != 2, "Reentrant call");
        _status = 2;
        _;
        _status = 1;
    }
}

/**
 * @title UncheckedCallFixed
 * @notice Fixed contract properly handling low-level call return values and errors with defense-in-depth reentrancy protection.
 */
contract UncheckedCallFixed is ReentrancyGuard {
    address public immutable owner;
    mapping(address => uint256) public rewards;

    event RewardPaid(address indexed recipient, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Caller not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function addReward(address user) external payable {
        rewards[user] += msg.value;
    }

    // Fixed 1: Pull pattern where caller claims own reward, verifying call return value and CEI
    function claimReward() external nonReentrant {
        uint256 amount = rewards[msg.sender];
        require(amount > 0, "No reward to claim");

        // Checks-Effects: state update and event before external interaction
        rewards[msg.sender] = 0;
        emit RewardPaid(msg.sender, amount);

        // Low-level call return boolean captured and required
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Reward transfer failed");
    }

    // Fixed 2: Return value of forwardCall verified with access control
    function forwardCall(address target, bytes calldata data) external onlyOwner returns (bytes memory) {
        require(target != address(0), "Invalid target address");
        (bool success, bytes memory result) = target.call(data);
        require(success, "Low-level call failed");
        return result;
    }
}
