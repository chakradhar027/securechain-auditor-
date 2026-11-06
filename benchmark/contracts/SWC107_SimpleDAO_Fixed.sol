// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SWC107_SimpleDAO_Fixed
 * @notice Fixed SWC-107 Reentrancy using Checks-Effects-Interactions and mutex guard.
 */
contract SWC107_SimpleDAO_Fixed {
    mapping(address => uint256) public credit;
    bool private _locked;

    modifier nonReentrant() {
        require(!_locked, "ReentrancyGuard: reentrant call");
        _locked = true;
        _;
        _locked = false;
    }

    function donate(address to) external payable {
        credit[to] += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(credit[msg.sender] >= amount, "Insufficient credit");
        // Checks-Effects: state update precedes interaction
        credit[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function queryCredit(address to) external view returns (uint256) {
        return credit[to];
    }
}

