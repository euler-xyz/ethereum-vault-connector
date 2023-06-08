// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../BaseLogic.sol";


/// @notice Activating and querying markets, and maintaining entered markets lists
contract Markets is BaseLogic {
    constructor(bytes32 moduleGitCommit_) BaseLogic(MODULEID__MARKETS, moduleGitCommit_) {}

    modifier governorOrEulerFactory {
        address msgSender = unpackTrailingParamMsgSender();

        require(msgSender == eulerFactory || msgSender == governorAdmin, "e/gov/unauthorized");

        _;
    }

    function registerMarket(address market) external nonReentrant governorOrEulerFactory {
        MarketStorage storage marketStorage = marketLookup[market];

        if (marketStorage.isRegistered) return;

        marketStorage.isRegistered = true;

        emit MarketRegistered(market);
    }

    function activateMarket(address market, uint8 hookBitmask, uint8 pauseBitmask) external nonReentrant {
        MarketStorage storage marketStorage = marketLookup[market];

        require(market != address(this), "e/markets/invalid-market");
        require(marketStorage.isRegistered, "e/markets/not-registred");
        require(!marketStorage.isActive, "e/markets/already-activated");

        address msgSender = unpackTrailingParamMsgSender();
        marketStorage.isActive = true;
        marketStorage.marketGovernor = msgSender == governorAdmin ? address(0) : msgSender;
        marketStorage.hookBitmask = hookBitmask;
        marketStorage.pauseBitmask = pauseBitmask;

        emit MarketActivated(market, msgSender, hookBitmask, pauseBitmask);
    }

    // getters

    /// @notice Retrieves the list of collateral markets for an account (assets enabled for collateral)
    /// @param account User account
    /// @return List of market addresses
    function getCollateralMarkets(address account) external view returns (address[] memory) {
        return getCollateralMarketsArray(account);
    }

    function getMarket(address market) external view returns (MarketStorage memory) {
        require(marketLookup[market].isActive, "e/market-not-activated");
        return marketLookup[market];
    }
}
