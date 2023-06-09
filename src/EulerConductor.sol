// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./Logic.sol";
import "./interfaces/IEulerMarketRegistry.sol";

interface IDeferredLiquidityCheck {
    function onDeferredLiquidityCheck(bytes memory data) external;
}

contract EulerConductor is Logic {
    string public constant name = "Euler Conductor";

    constructor(address admin, address registry) {
        emit Genesis();

        inBatchExecution = false;
        governorAdmin = admin;
        eulerMarketRegistry = registry;
    }


    // Governance

    function setEulerMarketRegistry(address newEulerMarketRegistry) external governorOnly {
        require(newEulerMarketRegistry != address(0), "e/conductor/bad-registry-address");
        eulerMarketRegistry = newEulerMarketRegistry;
        emit GovSetEulerMarketRegistry(newEulerMarketRegistry);
    }

    function setAccountOperator(uint subAccountId, address newOperator) external {
        address account = getSubAccount(msg.sender, subAccountId);
        accountOperators[account] = newOperator;
        emit GovSetAccountOperator(account, newOperator);
    }


    // Market activation

    function activateMarket(address market) external {
        require(market != address(this), "e/conductor/invalid-market");
        require(!isActive[market], "e/conductor/market-already-activated");
        require(IEulerMarketRegistry(eulerMarketRegistry).isRegistered(market), "e/conductor/market-not-registred");
        require(getLiabilityMarketsArray(market).length == 0, "e/conductor/market-cannot-have-liability");
        require(getCollateralMarketsArray(market).length == 0, "e/conductor/market-cannot-have-collateral");

        isActive[market] = true;
        activeMarkets.push(market);

        // TODO it would be best to check here that the market behaves correctly, i.e. that it's possible to
        // disable enabled liability, check liquidity etc.

        emit MarketActivated(market, msg.sender);
    }


    // Collateral/Liability arrays management

    function getCollateralMarkets(address account) external view returns (address[] memory) {
        return getCollateralMarketsArray(account);
    }

    function isCollateralMarketEnabled(address market, address account) external view returns (bool) {
        return isCollateralMarketAdded(account, market);
    }

    function enableCollateralMarket(address market, address account) public ownerOrOperator(account) liquidityCheck(account) {
        doAddCollateralMarket(account, market);
    }

    function disableCollateralMarket(address market, address account) public ownerOrOperator(account) liquidityCheck(account) {
        doRemoveCollateralMarket(account, market);
    }

    function getLiabilityMarkets(address account) external view returns (address[] memory) {
        return getLiabilityMarketsArray(account);
    }

    function isLiabilityMarketEnabled(address market, address account) external view returns (bool) {
        return isLiabilityMarketAdded(account, market);
    }

    function enableLiabilityMarket(address market, address account) public ownerOrOperator(account) liquidityCheck(account) {
        doAddLiabilityMarket(account, market);
    }

    function disableLiabilityMarket(address market, address account) external marketOnly(market) liquidityCheck(account) {
        doRemoveLiabilityMarket(account, market);
    }


    // Check liquidity

    function checkLiquidity(address account) external view returns (bool isLiquid) {
        return checkLiquidityInternal(account);
    }

    function computeLiquidity(address account) external view returns (IEulerRiskManager.LiquidityStatus memory) {
        return computeLiquidityInternal(account);
    }

    function computeLiquidities(address account) external view returns (IEulerRiskManager.MarketLiquidity[] memory) {
        return computeLiquiditiesInternal(account);
    }

    function computeLiquidation(address liquidator, address violator, address liability, address collateral) external view 
    returns (IEulerRiskManager.LiquidationOpportunity memory liqOpp, IEulerRiskManager.LiquidityStatus memory liqStat) {
        return computeLiquidationInternal(liquidator, violator, liability, collateral);
    }


    // Batching

    function deferLiquidityCheck(bytes memory data) external executeBatch {
        IDeferredLiquidityCheck(msg.sender).onDeferredLiquidityCheck(data);
    }

    function batchDispatch(EulerBatchItem[] calldata items) external executeBatch {
        doBatchDispatch(items, false);
    }

    function batchDispatchSimulate(EulerBatchItem[] calldata items) external executeBatch {
        doBatchDispatch(items, true);

        // TODO decide if really needed. commenting out for now to get rid of the warning
        //revert("e/conductor/simulation-did-not-revert");
    }

    function forwardCallToMarket(address market, address touchedAccount, bytes calldata data) external returns (bool success, bytes memory result) {
        return forwardCallToMarketInternal(market, touchedAccount, data);
    }


    // Getters

    function getGovernorAdmin() external view returns (address) {
        return governorAdmin;
    }

    function getEulerMarketRegistry() external view returns (address) {
        return eulerMarketRegistry;
    }

    function getAccountOperator(address account) external view returns (address) {
        return accountOperators[account];
    }

    function isMarketActive(address market) external view returns (bool) {
        return isActive[market];
    }

    function getActiveMarkets() external view returns (address[] memory) {
        return activeMarkets;
    }
}
