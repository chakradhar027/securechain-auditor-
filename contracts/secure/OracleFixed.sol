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
 * @title OracleFixed
 * @notice Fixed contract adopting decentralized Chainlink price feeds with staleness validation.
 */
contract OracleFixed {
    address public immutable owner;
    AggregatorV3Interface public immutable priceFeed;
    uint256 public constant HEARTBEAT = 3600; // 1 hour

    modifier onlyOwner() {
        require(msg.sender == owner, "Caller not owner");
        _;
    }

    constructor(address _priceFeed) {
        require(_priceFeed != address(0), "Invalid feed address");
        owner = msg.sender;
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    // Fixed: Uses Chainlink decentralized oracle with complete sanity and staleness checks
    function getAssetPrice() public view returns (uint256) {
        (
            uint80 roundId,
            int256 price,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();

        require(price > 0, "Non-positive oracle price");
        require(startedAt > 0, "Round not started");
        require(updatedAt > 0, "Incomplete round");
        require(answeredInRound >= roundId, "Stale round data");
        require(block.timestamp - updatedAt <= HEARTBEAT, "Stale price update");

        return uint256(price);
    }

    function calculateCollateralValue(uint256 tokenAmount) external view returns (uint256) {
        uint256 price = getAssetPrice();
        return (tokenAmount * price) / 1e18;
    }
}
