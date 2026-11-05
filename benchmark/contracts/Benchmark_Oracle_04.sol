// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

contract Benchmark_Oracle_04 {
    IUniswapV2Pair public pair;

    constructor(address _pair) {
        pair = IUniswapV2Pair(_pair);
    }

    // Vulnerable spot oracle calculation variant 4
    function queryPrice() external view returns (uint256) {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        return (uint256(r0) * 1e18) / uint256(r1);
    }
}
