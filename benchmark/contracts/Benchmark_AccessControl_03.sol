// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Benchmark_AccessControl_03 {
    address public admin;
    bool public isPaused;

    constructor() {
        admin = msg.sender;
    }

    // Missing access control on sensitive function variant 3
    function setAdmin(address newAdmin) external {
        
        admin = newAdmin;
    }

    function emergencyDrain(address payable recipient) external {
        
        recipient.transfer(address(this).balance);
    }
}
