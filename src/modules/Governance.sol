// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../BaseModule.sol";


contract Governance is BaseModule {
    constructor(bytes32 moduleGitCommit_) BaseModule(MODULEID__GOVERNANCE, moduleGitCommit_) {}

    modifier governorOnly {
        address msgSender = unpackTrailingParamMsgSender();

        require(msgSender == governorAdmin, "e/gov/unauthorized");

        _;
    }

    modifier marketGovernorOnly(address market) {
        MarketStorage storage marketStorage = marketLookup[market];
        require(marketStorage.isActive, "e/gov/market-not-activated");

        address marketGovernor = marketStorage.marketGovernor;
        address msgSender = unpackTrailingParamMsgSender();

        require((marketGovernor == address(0) && msgSender == governorAdmin) || msgSender == marketGovernor, "e/gov/unauthorized");

        _;
    }


    // setters

    function resetReentrancyLock() external nonReentrant governorOnly {
        reentrancyLock = REENTRANCYLOCK__INIT_STATE;
        
        emit GovResetReentrancy();
    }

    function setEulerFactory(address newEulerFactory) external nonReentrant governorOnly {
        require(newEulerFactory != address(0), "e/gov/bad-factory-addr");
        eulerFactory = newEulerFactory;
        emit GovSetEulerFactory(newEulerFactory);
    }

    function setMarketGovernor(address market, address newMarketGovernor) external nonReentrant marketGovernorOnly(market) {
        MarketStorage storage marketStorage = marketLookup[market];
        require(marketStorage.isActive, "e/gov/market-not-activated");

        marketStorage.marketGovernor = newMarketGovernor;
        emit GovSetMarketGovernor(market, newMarketGovernor);
    }

    function setHookBitmask(address market, uint8 newHookBitmask) external nonReentrant marketGovernorOnly(market) {
        MarketStorage storage marketStorage = marketLookup[market];
        require(marketStorage.isActive, "e/gov/market-not-activated");

        marketStorage.hookBitmask = newHookBitmask;
        emit GovSetHookBitmask(market, newHookBitmask);
    }

    function setPauseBitmask(address market, uint8 newPauseBitmask) external nonReentrant marketGovernorOnly(market) {
        MarketStorage storage marketStorage = marketLookup[market];
        require(marketStorage.isActive, "e/gov/market-not-activated");

        marketStorage.pauseBitmask = newPauseBitmask;
        emit GovSetPauseBitmask(market, newPauseBitmask);
    }

    function setAccountOperator(uint subAccountId, address newOperator) external nonReentrant {
        address msgSender = unpackTrailingParamMsgSender();
        address account = getSubAccount(msgSender, subAccountId);

        accountLookup[account].operator = newOperator;
        emit GovSetAccountOperator(account, newOperator);
    }


    // getters

    function getReentrancyLock() external view returns (uint) {
        return reentrancyLock;
    }

    function getEulerFactory() external view returns (address) {
        return eulerFactory;
    }
}
