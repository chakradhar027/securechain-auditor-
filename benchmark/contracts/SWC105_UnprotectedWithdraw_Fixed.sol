// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SWC105_UnprotectedWithdraw_Fixed
 * @notice Fixed SWC-105: Strict role-based access control protecting critical functions.
 */
contract SWC105_UnprotectedWithdraw_Fixed {
    address public owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event FundsWithdrawn(address indexed recipient, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not the owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {}

    function withdrawAll(address payable recipient) external onlyOwner {
        require(recipient != address(0), "Invalid recipient");
        uint256 balance = address(this).balance;
        require(balance > 0, "No funds to withdraw");
        emit FundsWithdrawn(recipient, balance);
        (bool ok, ) = recipient.call{value: balance}("");
        require(ok, "Transfer failed");
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

