// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Benchmark_AccessControl_02 {
    address public admin;
    bool public isPaused;

    constructor() {
        admin = msg.sender;
    }

    // Missing access control on sensitive function variant 2
    function setAdmin(address newAdmin) external {
        require(tx.origin == admin, 'Not admin');
        admin = newAdmin;
    }

    function emergencyDrain(address payable recipient) external {
        require(tx.origin == admin, 'Not admin');
        recipient.transfer(address(this).balance);
    }
}
