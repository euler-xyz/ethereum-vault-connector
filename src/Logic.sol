// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./Array.sol";
import "./Events.sol";
import "./interfaces/IEulerMarket.sol";
import "./interfaces/IEulerRiskManager.sol";

abstract contract Logic is Array, Events {
    struct EulerBatchItem {
        bool allowError;
        address touchedAccount;
        address target;
        bytes data;
    }

    struct EulerBatchItemResponse {
        bool success;
        bytes result;
    }

    error BatchDispatchSimulation(EulerBatchItemResponse[] simulation);


    // Modifiers

    modifier governorOnly {
        require(msg.sender == governorAdmin, "e/logic/governor-only");

        _;
    }

    modifier marketOnly(address market) {
        require(market == msg.sender, "e/logic/market-only");
        
        _;
    }

    modifier ownerOrOperator(address account) {
        require(
            isSubAccountOf(account,  msg.sender) || accountOperators[account] == msg.sender, 
            "e/logic/account-operator-only"
        );
        
        _;
    }

    modifier executeBatch() {
        inBatchExecution = true;

        _;

        inBatchExecution = false;

        requireLiquidityAll();
        checkMarketStatusAll();

        assert(transientArrays[LIQUIDITY_DEFERRAL_ARRAY_TYPE].numElements == 0);
        assert(transientArrays[MARKET_STATUS_ARRAY_TYPE].numElements == 0);
    }

    modifier marketStatusCheck(address market) {
        require(isActive[market], "e/logic/market-not-activated");

        bytes memory data;
        if (!arrayIncludes(transientArrays[MARKET_STATUS_ARRAY_TYPE], market)) {
            data = IEulerMarket(market).hook(HOOK__MARKET_FIRST_CALL, abi.encode(0));
        }

        _;

        if (!inBatchExecution) {
            IEulerMarket(market).hook(HOOK__MARKET_END_OF_TX, data);
        } else if (!arrayIncludes(transientArrays[MARKET_STATUS_ARRAY_TYPE], market)) {
            doAddElement(transientArrays[MARKET_STATUS_ARRAY_TYPE], market);
            transientMapping[market] = data;
        }
    }

    modifier liquidityCheck(address account) {
        _;
        
        // check liquidity for the account, but not if we're in the middle of a deferral
        if (!inBatchExecution) {
            requireLiquidityInternal(account);
        } else if (!arrayIncludes(transientArrays[LIQUIDITY_DEFERRAL_ARRAY_TYPE], account)) {
            doAddElement(transientArrays[LIQUIDITY_DEFERRAL_ARRAY_TYPE], account);
        }
    }


    // Account auth

    function getSubAccount(address primary, uint subAccountId) internal pure returns (address) {
        require(subAccountId < 256, "e/logic/sub-account-id-too-big");
        return address(uint160(primary) ^ uint160(subAccountId));
    }

    function isSubAccountOf(address primary, address subAccount) internal pure returns (bool) {
        return (uint160(primary) | 0xFF) == (uint160(subAccount) | 0xFF);
    }


    // Account collateral/liability array helper functions

    function getCollateralMarketsArray(address account) internal view returns (address[] memory) {
        return getArray(accountArrays[account][COLLATERAL_ARRAY_TYPE]);
    }

    function doAddCollateralMarket(address account, address market) internal {
        require(isActive[account], "e/logic/market-account-cannot-have-collateral");
        require(isActive[market], "e/logic/market-not-activated");
        doAddElement(accountArrays[account][COLLATERAL_ARRAY_TYPE], market);
    }

    function doRemoveCollateralMarket(address account, address market) internal {
        doRemoveElement(accountArrays[account][COLLATERAL_ARRAY_TYPE], market);
    }

    function isCollateralMarketAdded(address account, address market) view internal returns (bool) {
        return arrayIncludes(accountArrays[account][COLLATERAL_ARRAY_TYPE], market);
    }

    function getLiabilityMarketsArray(address account) internal view returns (address[] memory) {
        return getArray(accountArrays[account][LIABILITY_ARRAY_TYPE]);
    }

    function doAddLiabilityMarket(address account, address market) internal {
        require(isActive[account], "e/logic/market-account-cannot-have-liability");
        require(isActive[market], "e/logic/market-not-activated");
        doAddElement(accountArrays[account][LIABILITY_ARRAY_TYPE], market);
    }

    function doRemoveLiabilityMarket(address account, address market) internal {
        doRemoveElement(accountArrays[account][LIABILITY_ARRAY_TYPE], market);
    }

    function isLiabilityMarketAdded(address account, address market) view internal returns (bool) {
        return arrayIncludes(accountArrays[account][LIABILITY_ARRAY_TYPE], market);
    }


    // Batching

    function doBatchDispatch(EulerBatchItem[] calldata items, bool revertResponse) internal {
        EulerBatchItemResponse[] memory response;
        if (revertResponse) response = new EulerBatchItemResponse[](items.length);

        for (uint i = 0; i < items.length;) {
            EulerBatchItem calldata item = items[i];
            address targetAddr = item.target;
            bool success;
            bytes memory result;

            if (targetAddr == address(this)) {
                (success, result) = targetAddr.delegatecall(item.data);
            } else if (isActive[targetAddr]) {
                (success, result) = forwardCallToMarketInternal(targetAddr, item.touchedAccount, item.data);
            } else {
                (success, result) = targetAddr.call(item.data);
            }

            if (revertResponse) {
                EulerBatchItemResponse memory r = response[i];
                r.success = success;
                r.result = result;
            } else if (!(success || item.allowError)) {
                revertBytes(result);
            }

            unchecked { ++i; }
        }

        if (revertResponse) revert BatchDispatchSimulation(response);
    }

    function forwardCallToMarketInternal(address market, address account, bytes calldata data) internal
        ownerOrOperator(account)
        marketStatusCheck(market)
        liquidityCheck(account)
        returns (bool success, bytes memory result)
    {
        return market.call(abi.encodePacked(data, inBatchExecution, uint160(msg.sender), uint160(account)));

        // the market must check if the msg.sender is EulerConductor and if it is,
        // it must check that the trailing account address that was attached to the 
        // data is the the same as the account that was passed in calldata.
        // the above should ensure that:
        // 1) the msg.sender is authorized to act on behalf of the account
        // 2) liquidity check is deferred if in the batch

        // otoh, the liquidation flow may look as follows:
        // 1) liquidator calls liquidate() on a vault
        // 2) liquidate() calls computeLiquidation() on EulerConductor
        // 3) computeLiquidation() makes necessary checks and calls back into the vault
        //      (which implements RM interface) to compute the liquidation opportunity
        // 4) if the liquidation opportunity is valid, the vault transfers liability to
        //     the liquidator and calls into the collateral vault to seize the collateral.
        //     when seizing the collateral, the collateral vault must be sure that the
        //     call is safe. it must check that the msg.sender is EulerConductor and that
        //     the trailing msg.sender address and the account address that were  attached 
        //     to the calldata are both the same as the ONLY liability of the account from 
        //     which the collateral is being seized. in order to check the latter, the vault 
        //     must call getLiabilityMarkets(account from calldata from which collateral seized) 
        //     on EulerConductor and make appropriate checks.
        //
        //     if so, the forwarded call should look like this:
        //     forwardCallToMarket(collateral vault, liability vault, data encoding collateral seizure)
    }


    // Liquidity

    function checkLiquidityInternal(address account) internal view returns (bool isLiquid) {
        address[] memory liabilitiesArray = getLiabilityMarketsArray(account);
        
        if (liabilitiesArray.length == 0) return true;

        require(liabilitiesArray.length == 1, "e/logic/borrow-isolation-violation");
        
        address[] memory collateralsArray = getCollateralMarketsArray(account);

        // TODO try catch?
        return IEulerRiskManager(liabilitiesArray[0]).checkLiquidity(account, collateralsArray);
    }

    function computeLiquidityInternal(address account) internal view returns (IEulerRiskManager.LiquidityStatus memory) {
        address[] memory liabilitiesArray = getLiabilityMarketsArray(account);
        address[] memory collateralsArray = getCollateralMarketsArray(account);
        
        if (liabilitiesArray.length == 0) {
            uint collateralValue = 0;

            for (uint i = 0; i < collateralsArray.length;) {
                // TODO try catch?
                address collateral = collateralsArray[i];
                collateralValue += IEulerRiskManager(collateral).computeCollateralValue(account);
                unchecked { ++i; }
            }
            
            return IEulerRiskManager.LiquidityStatus({
                collateralValue: collateralValue, 
                liabilityValue: 0
            });
        } else {
            require(liabilitiesArray.length == 1, "e/logic/borrow-isolation-violation");

            // TODO try catch?
            return IEulerRiskManager(liabilitiesArray[0]).computeLiquidity(account, collateralsArray);
        }
    }

    function computeLiquiditiesInternal(address account) internal view returns (IEulerRiskManager.MarketLiquidity[] memory) {
        address[] memory liabilitiesArray = getLiabilityMarketsArray(account);
        address[] memory collateralsArray = getCollateralMarketsArray(account);
        
        if (liabilitiesArray.length == 0) {
            IEulerRiskManager.MarketLiquidity[] memory marketLiquidities = new IEulerRiskManager.MarketLiquidity[](collateralsArray.length);

            for (uint i = 0; i < collateralsArray.length;) {
                // TODO try catch?
                address collateral = collateralsArray[i];
                marketLiquidities[i] = IEulerRiskManager.MarketLiquidity({
                    market: collateral,
                    status: IEulerRiskManager.LiquidityStatus({
                        collateralValue: IEulerRiskManager(collateral).computeCollateralValue(account), 
                        liabilityValue: 0
                    })
                });
                unchecked { ++i; }
            }
            
            return marketLiquidities;
        } else {
            require(liabilitiesArray.length == 1, "e/logic/borrow-isolation-violation");

            // TODO try catch?
            return IEulerRiskManager(liabilitiesArray[0]).computeLiquidities(account, collateralsArray);
        }
    }

    function computeLiquidationInternal(address liquidator, address violator, address liability, address collateral) internal view 
    returns (IEulerRiskManager.LiquidationOpportunity memory liqOpp, IEulerRiskManager.LiquidityStatus memory liqStat) {
        require(!isSubAccountOf(liquidator, violator), "e/logic/self-liquidation");

        address[] memory liabilitiesArray = getLiabilityMarketsArray(violator);
        require(liabilitiesArray.length == 1 && liabilitiesArray[0] == liability, "e/logic/violator-liability-not-enabled");

        address[] memory collateralsArray = getCollateralMarketsArray(violator);
        uint seizeIndex = type(uint).max;
        
        for (uint i = 0; i < collateralsArray.length;) {
            if (collateralsArray[i] == collateral) {
                seizeIndex = i;
                break;
            }
            unchecked { ++i; }
        }

        require(seizeIndex != type(uint).max, "e/logic/violator-collateral-not-enabled");

        // TODO try catch?
        return IEulerRiskManager(liabilitiesArray[0]).computeLiquidation(liquidator, violator, collateralsArray, uint8(seizeIndex));
    }

    function requireLiquidityInternal(address account) internal view {
        require(checkLiquidityInternal(account), "e/logic/collateral-violation");
    }

    function requireLiquidityAll() internal {
        iterateExecuteAndClear(LIQUIDITY_DEFERRAL_ARRAY_TYPE);
    }


    // Market status check

    function checkMarketStatusAll() internal {
        iterateExecuteAndClear(MARKET_STATUS_ARRAY_TYPE);
    }


    // Error handling

    function revertBytes(bytes memory errMsg) internal pure {
        if (errMsg.length > 0) {
            assembly {
                revert(add(32, errMsg), mload(errMsg))
            }
        }

        revert("e/empty-error");
    }


    // Transient storage helper function

    function iterateExecuteAndClear(uint arrayType) private {
        ArrayStorage storage arrayStorage = transientArrays[arrayType];
        address firstElement = arrayStorage.firstElement;
        uint8 numElements = arrayStorage.numElements;

        if (numElements == 0) return;

        if (arrayType == LIQUIDITY_DEFERRAL_ARRAY_TYPE) {
            requireLiquidityInternal(firstElement);
        } else { //if (arrayType == MARKET_STATUS_ARRAY_TYPE) {
            IEulerMarket(firstElement).hook(HOOK__MARKET_END_OF_TX, transientMapping[firstElement]);
            delete transientMapping[firstElement];
        }
        
        if (numElements > 1) {
            for (uint i = 1; i < numElements;) {
                if (arrayType == LIQUIDITY_DEFERRAL_ARRAY_TYPE) {
                    requireLiquidityInternal(arrayStorage.elements[i]);
                } else { //if (arrayType == MARKET_STATUS_ARRAY_TYPE) {
                    address market = arrayStorage.elements[i];
                    IEulerMarket(market).hook(HOOK__MARKET_END_OF_TX, transientMapping[market]);
                    delete transientMapping[market];
                }
                
                delete arrayStorage.elements[i];
                unchecked { ++i; }
            }

            delete transientArrays[arrayType];
        }
    }
}
