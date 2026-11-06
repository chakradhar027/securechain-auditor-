// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
}

/**
 * @title RealWorld_PriceOracle_Fixed
 * @notice Fixed Chainlink decentralized oracle with strict freshness and round validation.
 */
contract RealWorld_PriceOracle_Fixed {
    AggregatorV3Interface public immutable priceFeed;
    uint256 public constant HEARTBEAT_TIMEOUT = 3600; // 1 hour

    constructor(address _feed) {
        require(_feed != address(0), "Invalid feed address");
        priceFeed = AggregatorV3Interface(_feed);
    }

    function getLatestPrice() external view returns (uint256) {
        (
            uint80 roundId,
            int256 price,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();

        require(price > 0, "Non-positive price");
        require(startedAt > 0, "Round not started");
        require(updatedAt > 0, "Incomplete round");
        require(answeredInRound >= roundId, "Stale round data");
        require(block.timestamp - updatedAt <= HEARTBEAT_TIMEOUT, "Price feed expired");

        return uint256(price);
    }
}

