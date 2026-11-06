// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SWC104_UncheckedSend_Fixed
 * @notice Fixed SWC-104: Return value of external transfer verified with CEI pattern.
 */
contract SWC104_UncheckedSend_Fixed {
    mapping(address => uint256) public userBalance;
    bool private _locked;

    modifier nonReentrant() {
        require(!_locked, "Reentrancy guard");
        _locked = true;
        _;
        _locked = false;
    }

    function deposit() external payable {
        userBalance[msg.sender] += msg.value;
    }

    function withdraw() external nonReentrant {
        uint256 amount = userBalance[msg.sender];
        require(amount > 0, "Zero balance");
        userBalance[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}

