// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

/**
 * @title OracleVulnerable
 * @notice Demonstrates spot AMM reserve price derivation vulnerable to flash loans.
 */
contract OracleVulnerable {
    IUniswapV2Pair public uniswapPair;

    constructor(address _pair) {
        uniswapPair = IUniswapV2Pair(_pair);
    }

    // Vulnerability: Spot AMM reserve pricing without TWAP or decentralized oracle
    function getAssetPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1, ) = uniswapPair.getReserves();
        require(reserve1 > 0, "Empty reserve");
        // Spot ratio can be distorted atomically via flash swaps
        return (uint256(reserve0) * 1e18) / uint256(reserve1);
    }

    function calculateCollateralValue(uint256 tokenAmount) external view returns (uint256) {
        uint256 price = getAssetPrice();
        return (tokenAmount * price) / 1e18;
    }
}
