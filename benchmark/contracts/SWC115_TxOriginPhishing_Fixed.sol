// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SWC115_TxOriginPhishing_Fixed
 * @notice Fixed SWC-115: Safe authentication using msg.sender instead of tx.origin.
 */
contract SWC115_TxOriginPhishing_Fixed {
    address public immutable owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Caller not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {}

    function transferTo(address payable dest, uint256 amount) external onlyOwner {
        require(dest != address(0), "Invalid destination");
        require(address(this).balance >= amount, "Insufficient balance");
        (bool ok, ) = dest.call{value: amount}("");
        require(ok, "Transfer failed");
    }
}

