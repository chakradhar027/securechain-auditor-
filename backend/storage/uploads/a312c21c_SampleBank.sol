
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    contract SampleBank {
        mapping(address => uint256) public balances;
        function deposit() external payable { balances[msg.sender] += msg.value; }
        function withdraw() external {
            uint256 b = balances[msg.sender];
            (bool s, ) = msg.sender.call{value: b}("");
            require(s);
            balances[msg.sender] = 0;
        }
    }
    