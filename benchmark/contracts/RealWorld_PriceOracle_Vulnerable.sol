// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

/**
 * @title RealWorld_PriceOracle_Vulnerable
 * @notice Vulnerable AMM spot price query vulnerable to flash loan manipulation.
 */
contract RealWorld_PriceOracle_Vulnerable {
    IUniswapV2Pair public immutable pair;

    constructor(address _pair) {
        pair = IUniswapV2Pair(_pair);
    }

    // Vulnerable: Direct spot reserve ratio query without time-weighted average price (TWAP)
    function getLatestPrice() external view returns (uint256) {
        (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
        require(reserve0 > 0 && reserve1 > 0, "Invalid reserves");
        return (uint256(reserve1) * 1e18) / uint256(reserve0);
    }
}

