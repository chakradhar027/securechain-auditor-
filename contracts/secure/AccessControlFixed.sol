// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AccessControlFixed
 * @notice Fixed contract adopting 2-step ownership and msg.sender authentication.
 */
contract AccessControlFixed {
    address public owner;
    address public pendingOwner;

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not the owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address invalid");
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "Caller is not the pending owner");
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    function emergencyWithdraw(address payable recipient) external onlyOwner {
        require(recipient != address(0), "Zero address invalid");
        uint256 bal = address(this).balance;
        (bool success, ) = recipient.call{value: bal}("");
        require(success, "Emergency transfer failed");
    }

    receive() external payable {}
}
