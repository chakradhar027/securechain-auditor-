// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SWC107_SimpleDAO_Vulnerable
 * @notice Canonical SWC-107 Reentrancy vulnerability based on The DAO exploit.
 * State balance is deducted AFTER the external call, permitting reentrant drains.
 */
contract SWC107_SimpleDAO_Vulnerable {
    mapping(address => uint256) public credit;

    function donate(address to) external payable {
        credit[to] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(credit[msg.sender] >= amount, "Insufficient credit");
        // Vulnerable: External call before state balance reduction
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        credit[msg.sender] -= amount;
    }

    function queryCredit(address to) external view returns (uint256) {
        return credit[to];
    }
}

