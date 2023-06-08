// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./BaseModule.sol";
import "./interfaces/IRiskManager.sol";
import "./interfaces/IEulerMarket.sol";


abstract contract BaseLogic is BaseModule {
    struct MarketCache {
        address marketAddress;
        address marketGovernor;
        uint8 hookBitmask;
        uint8 pauseBitmask;
    }


    constructor(uint moduleId_, bytes32 moduleGitCommit_) BaseModule(moduleId_, moduleGitCommit_) {}


    // Modifiers

    modifier accountOperatorOnly(address primary, uint subAccountId) {
        {
            address msgSender = unpackTrailingParamMsgSender();
            address account = getSubAccount(primary, subAccountId);

            require(primary == msgSender || accountLookup[account].operator == msgSender, "e/account-operator-only");
        }
        
        _;
    }

    modifier marketOnly(address market) {
        {
            address msgSender = unpackTrailingParamMsgSender();

            require(market == msgSender, "e/market-only");
        }
        
        _;
    }

    modifier reentrantBatch() {
        reentrancyLock |= REENTRANCYLOCK__DEFERRAL;

        _;

        requireLiquidityAll();
        checkMarketStatusAll();

        reentrancyLock &= ~REENTRANCYLOCK__DEFERRAL;

        assert(transientArrays[LIQUIDITY_DEFERRAL_ARRAY_TYPE].numElements == 0);
        assert(transientArrays[OPERATED_MARKETS_ARRAY_TYPE].numElements == 0);
    }

    modifier marketStatusCheck(address market) {
        checkReentrancyLockedAndSetInMarketStatusCheck();

        _;
        
        // validate if should, but not if we're in the middle of a deferral
        if (isHookActive(market, HOOK__MARKET_END_OF_TX)) {
            if ((REENTRANCYLOCK__DEFERRAL & reentrancyLock) == 0) {
                IEulerMarket(market).hook(HOOK__MARKET_END_OF_TX, abi.encode(0));
            } else if (!arrayIncludes(transientArrays[OPERATED_MARKETS_ARRAY_TYPE], market)) {
                doAddElement(transientArrays[OPERATED_MARKETS_ARRAY_TYPE], market);
            }
        }
    }

    // this modifier must be used for all nonReentrant functions
    modifier liquidityCheck(address primary, uint subAccountId) {
        checkReentrancyLockedAndSetInLiquidityCheck();

        _;
        
        // check liquidity for the account but not if we're in the middle of a deferral
        if (primary != address(0)) {
            address account = getSubAccount(primary, subAccountId);

            if ((REENTRANCYLOCK__DEFERRAL & reentrancyLock) == 0) {
                requireLiquidity(account);
            } else if (!arrayIncludes(transientArrays[LIQUIDITY_DEFERRAL_ARRAY_TYPE], account)) {
                doAddElement(transientArrays[LIQUIDITY_DEFERRAL_ARRAY_TYPE], account);
            }
        }
    }


    // Auxiliary functions for modifiers

    function checkReentrancyLockedAndSetInMarketStatusCheck() internal {
        require((REENTRANCYLOCK__LOCK & reentrancyLock) != 0, "e/reentrancy-not-locked");

        reentrancyLock |= REENTRANCYLOCK__IN_MARKET_STATUS_CHECK;
    }

    function checkReentrancyLockedAndSetInLiquidityCheck() internal {
        require((REENTRANCYLOCK__LOCK & reentrancyLock) != 0, "e/reentrancy-not-locked");

        reentrancyLock |= REENTRANCYLOCK__IN_LIQUIDITY_CHECK;
    }

    function setReentrancyUnlocked() internal override {
        // enforces liquidity check on every nonReentrant function
        require((REENTRANCYLOCK__IN_LIQUIDITY_CHECK & reentrancyLock) != 0, "e/reentrancy-not-in-liquidity-check");
        //require((REENTRANCYLOCK__IN_MARKET_CHECK_STATUS & reentrancyLock) != 0, "e/reentrancy-not-in-validate");
        
        reentrancyLock &= ~(REENTRANCYLOCK__LOCK | REENTRANCYLOCK__IN_LIQUIDITY_CHECK | REENTRANCYLOCK__IN_MARKET_STATUS_CHECK);
    }


    // Array drivers

    function getArray(ArrayStorage storage arrayStorage) private view returns (address[] memory) {
        address firstElement = arrayStorage.firstElement;
        uint8 numElements = arrayStorage.numElements;

        address[] memory output = new address[](numElements);
        if (numElements == 0) return output;

        output[0] = firstElement;

        for (uint i = 1; i < numElements;) {
            output[i] = arrayStorage.elements[i];
            unchecked { ++i; }
        }

        return output;
    }

    function doAddElement(ArrayStorage storage arrayStorage, address element) private {
        address firstElement = arrayStorage.firstElement;
        uint8 numElements = arrayStorage.numElements;

        if (numElements != 0) {
            if (firstElement == element) return; // already in the first position
            for (uint i = 1; i < numElements;) {
                if (arrayStorage.elements[i] == element) return; // already in the array
                unchecked { ++i; }
            }
        }

        require(numElements < MAX_SUBACCOUNT_ELEMENTS, "e/too-many-elements");

        if (numElements == 0) arrayStorage.firstElement = element;
        else arrayStorage.elements[numElements] = element;

        arrayStorage.numElements = numElements + 1;
    }

    function doRemoveElement(ArrayStorage storage arrayStorage, address element) private {
        address firstElement = arrayStorage.firstElement;
        uint8 numElements = arrayStorage.numElements;
        uint searchIndex = type(uint).max;

        if (numElements == 0) return; // already exited

        if (firstElement == element) {
            searchIndex = 0;
        } else {
            for (uint i = 1; i < numElements;) {
                if (arrayStorage.elements[i] == element) {
                    searchIndex = i;
                    break;
                }
                unchecked { ++i; }
            }

            if (searchIndex == type(uint).max) return; // already exited
        }

        uint lastMarketIndex = numElements - 1;

        if (searchIndex != lastMarketIndex) {
            if (searchIndex == 0) arrayStorage.firstElement = arrayStorage.elements[lastMarketIndex];
            else arrayStorage.elements[searchIndex] = arrayStorage.elements[lastMarketIndex];
        }

        arrayStorage.numElements = uint8(lastMarketIndex);

        if (lastMarketIndex != 0) delete arrayStorage.elements[lastMarketIndex]; // zero out for storage refund
    }

    function arrayIncludes(ArrayStorage storage arrayStorage, address element) private view returns (bool) {
        address firstElement = arrayStorage.firstElement;
        uint8 numElements = arrayStorage.numElements;

        if (numElements == 0) return false;
        if (firstElement == element) return true;

        for (uint i = 1; i < numElements;) {
            if (arrayStorage.elements[i] == element) return true;
            unchecked { ++i; }
        }

        return false;
    }

    // Account arrays helper functions

    function getCollateralMarketsArray(address account) internal view returns (address[] memory) {
        return getArray(accountArrays[account][COLLATERAL_ARRAY_TYPE]);
    }

    function doAddCollateralMarket(address account, address market) internal {
        doAddElement(accountArrays[account][COLLATERAL_ARRAY_TYPE], market);
        emit AddCollateral(market, account);
    }

    function doRemoveCollateralMarket(address account, address market) internal {
        doRemoveElement(accountArrays[account][COLLATERAL_ARRAY_TYPE], market);
        emit RemoveCollateral(market, account);
    }

    function isCollateralMarketAdded(address account, address market) view internal returns (bool) {
        return arrayIncludes(accountArrays[account][COLLATERAL_ARRAY_TYPE], market);
    }

    function getLiabilitiesMarketsArray(address account) internal view returns (address[] memory) {
        return getArray(accountArrays[account][LIABILITY_ARRAY_TYPE]);
    }

    function doAddLiabilityMarket(address account, address market) internal {
        doAddElement(accountArrays[account][LIABILITY_ARRAY_TYPE], market);
    }

    function doRemoveLiabilityMarket(address account, address market) internal {
        doRemoveElement(accountArrays[account][LIABILITY_ARRAY_TYPE], market);
    }

    function isLiabilityMarketAdded(address account, address market) view internal returns (bool) {
        return arrayIncludes(accountArrays[account][LIABILITY_ARRAY_TYPE], market);
    }


    // Cache

    function loadMarketCache(address market) internal returns (MarketCache memory marketCache) {
        MarketStorage storage marketStorage = marketLookup[market];
        require(marketStorage.isActive, "e/market-not-activated");
        
        marketCache.marketAddress = market;
        marketCache.marketGovernor = marketStorage.marketGovernor;
        marketCache.hookBitmask = marketStorage.hookBitmask;
        marketCache.pauseBitmask = marketStorage.pauseBitmask;

        if (isHookActive(marketCache, HOOK__MARKET_LOAD_CACHE) && !arrayIncludes(transientArrays[OPERATED_MARKETS_ARRAY_TYPE], market)) {
            IEulerMarket(market).hook(HOOK__MARKET_LOAD_CACHE, abi.encode(0));
        }
    }


    // Lending functions

    function doTouch(address market) internal {
        IEulerMarket(market).touch();
    }

    function doDeposit(address market, address primary, uint subAccountId, uint amount, address msgSender) internal {
        MarketCache memory marketCache = loadMarketCache(market);
        checkPause(marketCache, PAUSE__DEPOSIT);

        IEulerMarket(market).deposit(primary, subAccountId, amount, msgSender);
    }

    function doWithdraw(address market, address primary, uint subAccountId, uint amount) internal {
        MarketCache memory marketCache = loadMarketCache(market);
        checkPause(marketCache, PAUSE__WITHDRAW);

        IEulerMarket(market).withdraw(primary, subAccountId, amount);
    }

    function doBorrow(address market, address primary, uint subAccountId, uint amount) internal {
        MarketCache memory marketCache = loadMarketCache(market);
        checkPause(marketCache, PAUSE__BORROW);

        if (IEulerMarket(market).borrow(primary, subAccountId, amount)) {
            doAddLiabilityMarket(getSubAccount(primary, subAccountId), market);
        }
    }

    function doRepay(address market, address primary, uint subAccountId, uint amount) internal {
        MarketCache memory marketCache = loadMarketCache(market);
        checkPause(marketCache, PAUSE__REPAY);

        if (!IEulerMarket(market).repay(primary, subAccountId, amount)) {
            doRemoveLiabilityMarket(getSubAccount(primary, subAccountId), market);
        }
    }

    function doDepositAndBorrow(address market, address primary, uint subAccountId, uint amount) internal {
        MarketCache memory marketCache = loadMarketCache(market);
        checkPause(marketCache, PAUSE__MINT);

        if (IEulerMarket(market).depositAndBorrow(primary, subAccountId, amount)) {
            doAddLiabilityMarket(getSubAccount(primary, subAccountId), market);
        }
    }

    function doRepayAndWithdraw(address market, address primary, uint subAccountId, uint amount) internal {
        MarketCache memory marketCache = loadMarketCache(market);
        checkPause(marketCache, PAUSE__BURN);

        if (!IEulerMarket(market).repayAndWithdraw(primary, subAccountId, amount)) {
            doRemoveLiabilityMarket(getSubAccount(primary, subAccountId), market);
        }
    }


    // Transient storage helper function

    function iterateExecuteAndClear(uint arrayType) private {
        ArrayStorage storage arrayStorage = transientArrays[arrayType];
        address firstElement = arrayStorage.firstElement;
        uint8 numElements = arrayStorage.numElements;

        if (numElements == 0) return;

        if (arrayType == LIQUIDITY_DEFERRAL_ARRAY_TYPE) {
            requireLiquidity(firstElement);
        } else { //if (arrayType == OPERATED_MARKETS_ARRAY_TYPE) {
            IEulerMarket(firstElement).hook(HOOK__MARKET_END_OF_TX, abi.encode(0));
        }
        
        if (numElements > 1) {
            for (uint i = 1; i < numElements;) {
                if (arrayType == LIQUIDITY_DEFERRAL_ARRAY_TYPE) {
                    requireLiquidity(arrayStorage.elements[i]);
                } else { //if (arrayType == OPERATED_MARKETS_ARRAY_TYPE) {
                    IEulerMarket(arrayStorage.elements[i]).hook(HOOK__MARKET_END_OF_TX, abi.encode(0));
                }
                
                delete arrayStorage.elements[i];
                unchecked { ++i; }
            }

            delete transientArrays[arrayType];
        }
    }

    // Liquidity

    function checkLiquidityInternal(address account) internal view returns (bool isLiquid) {
        address[] memory liabilitiesArray = getLiabilitiesMarketsArray(account);
        
        if (liabilitiesArray.length == 0) return true;

        require(liabilitiesArray.length == 1, "e/borrow-isolation-violation");
        
        address liability = liabilitiesArray[0];
        address[] memory collateralsArray = getCollateralMarketsArray(account);

        // TODO try catch?
        return IRiskManager(liability).checkLiquidity(account, liability, collateralsArray);
    }

    function requireLiquidity(address account) internal {
        require(checkLiquidityInternal(account), "e/collateral-violation");

        accountLookup[account].lastAccountUpdate = uint40(block.timestamp);
    }

    function requireLiquidityAll() internal {
        iterateExecuteAndClear(LIQUIDITY_DEFERRAL_ARRAY_TYPE);
    }


    // Hooks handling

    function checkMarketStatusAll() internal {
        iterateExecuteAndClear(OPERATED_MARKETS_ARRAY_TYPE);
    }


    // Market Bitmasks

    function isHookActive(address market, uint8 hookNumber) internal view returns (bool) {
        return (marketLookup[market].hookBitmask & (1 << hookNumber)) != 0;
    }

    function isHookActive(MarketCache memory marketCache, uint8 hookNumber) internal pure returns (bool) {
        return (marketCache.hookBitmask & (1 << hookNumber)) != 0;
    }

    function checkPause(MarketCache memory marketCache, uint8 mask) internal pure {
        require((marketCache.pauseBitmask & (mask | PAUSE__COMPLETE)) == 0, "e/market-operation-paused");
    }
}
