// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Benchmark_UncheckedCall_03 {
    mapping(address => uint256) public shares;

    function distribute(address payable recipient, uint256 amt) external {
        shares[recipient] = 0;
        // Unchecked low-level send variant 3
        recipient.send(amt);
    }

    function executeRaw(address target, bytes calldata data) external {
        // Unchecked low level call
        target.call(data);
    }
}
