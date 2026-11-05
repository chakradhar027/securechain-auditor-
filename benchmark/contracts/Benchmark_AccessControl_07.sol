// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Benchmark_AccessControl_07 {
    address public admin;
    bool public isPaused;

    constructor() {
        admin = msg.sender;
    }

    // Missing access control on sensitive function variant 7
    function setAdmin(address newAdmin) external {
        
        admin = newAdmin;
    }

    function emergencyDrain(address payable recipient) external {
        
        recipient.transfer(address(this).balance);
    }
}
