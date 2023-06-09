// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./TransientStorage.sol";

interface IEulerMarketRegistry {
    function isRegistered(address market) external returns (bool);
}

interface IEulerMarket {
    function disableLiabilityMarket(address account) external;
    function checkLiquidity(address account, address[] memory collaterals) external view returns (bool isLiquid);
    function hook(uint hookNumber, bytes memory data) external returns (bytes memory);
}

interface IDeferredChecks {
    function onDeferredChecks(bytes memory data) external;
}


contract EulerConductor is TransientStorage {
    // Constants

    string public constant name = "Euler Conductor";

    uint internal constant EXEC_STATE__INITIAL_STATE = 1 << 0;
    uint internal constant EXEC_STATE__REENTRANCY_LOCK = 1 << 1;
    uint internal constant EXEC_STATE__DEFERRED_CHECKS = 1 << 2;

    uint internal constant COLLATERAL_ARRAY_TYPE = 0;
    uint internal constant LIABILITY_ARRAY_TYPE = 1;

    uint internal constant LIQUIDITY_DEFERRAL_ARRAY_TYPE = 0;
    uint internal constant MARKET_STATUS_ARRAY_TYPE = 1;

    uint internal constant HOOK__MARKET_FIRST_TOUCHED = 0;
    uint internal constant HOOK__MARKET_SUMMARY = 1;


    // Storage 

    address public governorAdmin;
    address public eulerMarketRegistry;
    mapping(address => bool) public isMarketActive;
    mapping(address => address) public accountOperators;

    uint internal executionState;
    mapping(address => ArrayStorage[2]) internal accountArrays;
    address[] internal activeMarkets;


    // Events, Errors

    event Genesis();
    event MarketActivated(address indexed market, address indexed marketCreator);

    event GovernorAdminSet(address indexed admin);
    event EulerMarketRegistrySet(address indexed registry);
    event AccountOperatorSet(address indexed account, address operator);
    
    event ReferralCode(bytes32 indexed referralCode);

    error BatchDispatchSimulation(EulerBatchItemResponse[] simulation);


    // Constructor

    constructor(address admin, address registry) {
        emit Genesis();

        executionState = EXEC_STATE__INITIAL_STATE;
        governorAdmin = admin;
        eulerMarketRegistry = registry;
    }


    // Modifiers

    modifier governorOnly {
        require(msg.sender == governorAdmin, "e/governor-only");
        _;
    }

    modifier marketOnly(address market) {
        require(market == msg.sender, "e/market-only");
        _;
    }

    modifier ownerOrOperator(address account) {
        require(
            ((uint160(msg.sender) | 0xFF) == (uint160(account) | 0xFF)) || accountOperators[account] == msg.sender, 
            "e/account-operator-only"
        );
        
        _;
    }

    modifier nonReentrant {
        require((executionState & EXEC_STATE__REENTRANCY_LOCK) == 0, "e/reentrant-call");
        executionState |= EXEC_STATE__REENTRANCY_LOCK;

        _;

        executionState &= ~EXEC_STATE__REENTRANCY_LOCK;
    }

    modifier defer() {
        executionState |= EXEC_STATE__DEFERRED_CHECKS;

        _;

        executionState &= ~EXEC_STATE__DEFERRED_CHECKS;

        iterateExecuteAndClear(LIQUIDITY_DEFERRAL_ARRAY_TYPE);
        iterateExecuteAndClear(MARKET_STATUS_ARRAY_TYPE);

        assert(transientArrays[LIQUIDITY_DEFERRAL_ARRAY_TYPE].numElements == 0);
        assert(transientArrays[MARKET_STATUS_ARRAY_TYPE].numElements == 0);
    }

    modifier marketStatusCheck(address market) {
        // skip the check if the address is not an active market
        if (!isMarketActive[market]) {
            _;
            return;
        }

        bytes memory data;
        if (!arrayIncludes(transientArrays[MARKET_STATUS_ARRAY_TYPE], market)) {
            data = IEulerMarket(market).hook(HOOK__MARKET_FIRST_TOUCHED, abi.encode(0));
        }

        _;

        if ((executionState & EXEC_STATE__DEFERRED_CHECKS) == 0) {
            IEulerMarket(market).hook(HOOK__MARKET_SUMMARY, data);
        } else if (!arrayIncludes(transientArrays[MARKET_STATUS_ARRAY_TYPE], market)) {
            doAddElement(transientArrays[MARKET_STATUS_ARRAY_TYPE], market);
            transientMapping[market] = data;
        }
    }

    modifier liquidityCheck(address account) {
        _;
        
        // check liquidity for the account, but not if we're in the middle of a deferral
        if ((executionState & EXEC_STATE__DEFERRED_CHECKS) == 0) {
            requireLiquidityInternal(account);
        } else if (!arrayIncludes(transientArrays[LIQUIDITY_DEFERRAL_ARRAY_TYPE], account)) {
            doAddElement(transientArrays[LIQUIDITY_DEFERRAL_ARRAY_TYPE], account);
        }
    }

    modifier registerReferralCode(bytes32 code) {
        if (code != bytes32(0)) emit ReferralCode(code);
        _;
    }


    // Governance

    function setGovernorAdmin(address newGovernorAdmin) external governorOnly {
        governorAdmin = newGovernorAdmin;
        emit GovernorAdminSet(newGovernorAdmin);
    }

    function setEulerMarketRegistry(address newEulerMarketRegistry) external governorOnly {
        require(newEulerMarketRegistry != address(0), "e/bad-registry-address");
        eulerMarketRegistry = newEulerMarketRegistry;
        emit EulerMarketRegistrySet(newEulerMarketRegistry);
    }


    // Market activation

    function activateMarket(address market) external nonReentrant {
        require(market != address(this), "e/invalid-market");
        require(!isMarketActive[market], "e/market-already-activated");
        require(IEulerMarketRegistry(eulerMarketRegistry).isRegistered(market), "e/market-not-registred");

        isMarketActive[market] = true;
        activeMarkets.push(market);

        // assure that the market is implemented correctly
        enableLiabilityMarket(market, msg.sender);
        IEulerMarket(market).disableLiabilityMarket(msg.sender);

        bytes memory data = IEulerMarket(market).hook(HOOK__MARKET_FIRST_TOUCHED, abi.encode(0));
        IEulerMarket(market).hook(HOOK__MARKET_SUMMARY, data);

        address[] memory collaterals = new address[](0);
        require(IEulerMarket(market).checkLiquidity(msg.sender, collaterals), "e/dry-liquidity-check-invalid");

        emit MarketActivated(market, msg.sender);
    }

    function getActiveMarkets() external view returns (address[] memory) {
        return activeMarkets;
    }


    // Account operators

    function setAccountOperator(uint subAccountId, address newOperator) external {
        require(subAccountId < 256, "e/sub-account-id-too-big");
        address account = address(uint160(msg.sender) ^ uint160(subAccountId));

        accountOperators[account] = newOperator;
        emit AccountOperatorSet(account, newOperator);
    }


    // Collateral management

    function getCollateralMarkets(address account) external view returns (address[] memory) {
        return getArray(accountArrays[account][COLLATERAL_ARRAY_TYPE]);
    }

    function isCollateralMarketEnabled(address market, address account) external view returns (bool) {
        return arrayIncludes(accountArrays[account][COLLATERAL_ARRAY_TYPE], market);
    }

    function enableCollateralMarket(address market, address account) external ownerOrOperator(account) liquidityCheck(account) {
        require(isMarketActive[market], "e/market-not-activated");
        doAddElement(accountArrays[account][COLLATERAL_ARRAY_TYPE], market);
    }

    function disableCollateralMarket(address market, address account) external ownerOrOperator(account) liquidityCheck(account) {
        doRemoveElement(accountArrays[account][COLLATERAL_ARRAY_TYPE], market);
    }


    // Liability management

    function getLiabilityMarkets(address account) external view returns (address[] memory) {
        return getArray(accountArrays[account][LIABILITY_ARRAY_TYPE]);
    }

    function isLiabilityMarketEnabled(address market, address account) external view returns (bool) {
        return arrayIncludes(accountArrays[account][LIABILITY_ARRAY_TYPE], market);
    }

    function enableLiabilityMarket(address market, address account) public ownerOrOperator(account) liquidityCheck(account) {
        require(isMarketActive[market], "e/market-not-activated");
        doAddElement(accountArrays[account][LIABILITY_ARRAY_TYPE], market);
    }

    function disableLiabilityMarket(address market, address account) external marketOnly(market) liquidityCheck(account) {
        doRemoveElement(accountArrays[account][LIABILITY_ARRAY_TYPE], market);
    }


    // Batching

    function deferChecks(bytes memory data) external defer {
        IDeferredChecks(msg.sender).onDeferredChecks(data);
    }

    function batchDispatch(EulerBatchItem[] calldata items, bytes32 referralCode) external defer {
        doBatchDispatch(items, referralCode, false);
    }

    function batchDispatchSimulate(EulerBatchItem[] calldata items, bytes32 referralCode) external defer {
        doBatchDispatch(items, referralCode, true);

        // TODO decide if really needed. commenting out for now to get rid of the warning
        //revert("e/simulation-did-not-revert");
    }


    // Call forwarding

    function execute(address targetContract, address targetAccount, bytes calldata data) external returns (bool success, bytes memory result) {
        return executeInternal(targetContract, targetAccount, data);
    }

    function forward(address targetContract, address targetAccount, bytes calldata data) external returns (bool success, bytes memory result) {
        return forwardInternal(targetContract, targetAccount, data);
    }


    // Liquidity check

    function checkLiquidity(address account) external view returns (bool isLiquid) {
        return checkLiquidityInternal(account);
    }



    // INTERNAL FUNCTIONS

    function doBatchDispatch(EulerBatchItem[] calldata items, bytes32 referralCode, bool revertResponse) internal registerReferralCode(referralCode) {
        EulerBatchItemResponse[] memory response;
        if (revertResponse) response = new EulerBatchItemResponse[](items.length);

        for (uint i = 0; i < items.length;) {
            EulerBatchItem calldata item = items[i];
            address targetContract = item.targetContract;
            bool success;
            bytes memory result;

            if (targetContract == address(this)) {
                (success, result) = targetContract.delegatecall(item.data);
            } else {
                (success, result) = executeInternal(targetContract, item.targetAccount, item.data);
            }

            if (revertResponse) {
                response[i].success = success;
                response[i].result = result;
            } else if (!(success || item.allowError)) {
                if (result.length > 0) {
                    assembly {
                        revert(add(32, result), mload(result))
                    }
                }

                revert("e/empty-error");
            }

            unchecked { ++i; }
        }

        if (revertResponse) revert BatchDispatchSimulation(response);
    }

    function executeInternal(address targetContract, address targetAccount, bytes calldata data) internal
        nonReentrant
        marketStatusCheck(targetContract)
        ownerOrOperator(targetAccount)
        liquidityCheck(targetAccount)
        returns (bool success, bytes memory result)
    {
        require(targetContract != address(this), "e/invalid-target");
        
        return targetContract.call(
            abi.encodePacked(
                data, 
                uint160(targetAccount), 
                (executionState & EXEC_STATE__DEFERRED_CHECKS) != 0
            )
        );

        // this function executes arbitrary calldata on a target contract.
        // if a target is an active market, the market status is checked.
        // the function checks whether the msg.sender is authorized to act on behalf
        // of the targetAccount and liquidity check on that account is performed.

        // the target contract must check if the msg.sender is EulerConductor and if 
        // the trailing targetAccount address that is attached to the data is the 
        // the same as the account on which the operation will be performed (according 
        // to the calldata). if both conditions are met, it ensures that the msg.sender 
        // is authorized to act on behalf of the targetAccount.
        // additionally, if the trailing boolean flag is set, it means that
        // the liquidity check and market status check (if applicable) are deferred.
    }

    function forwardInternal(address targetContract, address targetAccount, bytes calldata data) internal
        nonReentrant
        marketStatusCheck(targetContract)
        liquidityCheck(targetAccount)
        returns (bool success, bytes memory result)
    {
        address[] memory liabilities = getArray(accountArrays[targetAccount][LIABILITY_ARRAY_TYPE]);

        require(liabilities.length == 1 && liabilities[0] == msg.sender, "e/liability-not-in-control");
        require(arrayIncludes(accountArrays[targetAccount][COLLATERAL_ARRAY_TYPE], targetContract), "e/collateral-not-enabled");

        return targetContract.call(
            abi.encodePacked(
                data, 
                uint160(targetAccount), 
                (executionState & EXEC_STATE__DEFERRED_CHECKS) != 0
            )
        );

        // this function executes arbitrary calldata on a target contract.
        // the function checks whether the msg.sender is authorized to call the target
        // by checking if the msg.sender is the only liability of the targetAccount
        // (such a liability vault is in control) and if the target is enabled as collateral.
        // the market status is checked for the target contract as the target contract
        // is always an active market (otherwise it wouldn't be enabled as collateral). 
        // the liquidity check is always performed on the targetAccount.

        // this function helps the liquidation flow which may look as follows:
        // 1) liquidator enables the liability asset to be taken over
        // 2) liquidator calls liquidate() on a liability vault
        //      if done from a batch, the vault should verify that the msg.sender is authorized 
        //      to act on behalf of the liquidator and that the checks are deferred (liquidity check
        //      for a liquidator and market status check for the liability vault), as described 
        //      in executeInternal()
        // 3) liability vault transfers the liability from the violator to the liquidator.
        //    it must be ensured that the liquidator had enabled the liability before the liquidation
        // 4) liability valut instructs the collateral vault to give up violator's collateral.
        //    in order to do that, the liability vault must use forward() function encoding 
        //    withdraw() action in the calldata to be fowarded. the forward() function should be 
        //    called as follows:
        //    EulerConductor.forward(collateral vault, violator, data encoding collateral withdrawal from the violator)
    }


    // Liquidity check internals

    function checkLiquidityInternal(address account) internal view returns (bool isLiquid) {
        address[] memory liabilities = getArray(accountArrays[account][LIABILITY_ARRAY_TYPE]);
        
        if (liabilities.length == 0) return true;

        require(liabilities.length == 1, "e/borrow-isolation-violation");
        
        address[] memory collaterals = getArray(accountArrays[account][COLLATERAL_ARRAY_TYPE]);

        return IEulerMarket(liabilities[0]).checkLiquidity(account, collaterals);
    }

    function requireLiquidityInternal(address account) internal view {
        require(checkLiquidityInternal(account), "e/collateral-violation");
    }


    // Arrays helper functions

    function doAddElement(ArrayStorage storage arrayStorage, address element) internal {
        address firstElement = arrayStorage.firstElement;
        uint8 numElements = arrayStorage.numElements;

        if (numElements != 0) {
            if (firstElement == element) return; // already in the first position
            for (uint i = 1; i < numElements;) {
                if (arrayStorage.elements[i] == element) return; // already in the array
                unchecked { ++i; }
            }
        }

        require(numElements < MAX_PRESENT_ELEMENTS, "e/array/too-many-elements");

        if (numElements == 0) arrayStorage.firstElement = element;
        else arrayStorage.elements[numElements] = element;

        arrayStorage.numElements = numElements + 1;
    }

    function doRemoveElement(ArrayStorage storage arrayStorage, address element) internal {
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

    function getArray(ArrayStorage storage arrayStorage) internal view returns (address[] memory) {
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

    function arrayIncludes(ArrayStorage storage arrayStorage, address element) internal view returns (bool) {
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

    function iterateExecuteAndClear(uint arrayType) private {
        ArrayStorage storage arrayStorage = transientArrays[arrayType];
        address firstElement = arrayStorage.firstElement;
        uint8 numElements = arrayStorage.numElements;

        if (numElements == 0) return;

        if (arrayType == LIQUIDITY_DEFERRAL_ARRAY_TYPE) {
            requireLiquidityInternal(firstElement);
        } else { //if (arrayType == MARKET_STATUS_ARRAY_TYPE) {
            IEulerMarket(firstElement).hook(HOOK__MARKET_SUMMARY, transientMapping[firstElement]);
            delete transientMapping[firstElement];
        }
        
        if (numElements > 1) {
            for (uint i = 1; i < numElements;) {
                if (arrayType == LIQUIDITY_DEFERRAL_ARRAY_TYPE) {
                    requireLiquidityInternal(arrayStorage.elements[i]);
                } else { //if (arrayType == MARKET_STATUS_ARRAY_TYPE) {
                    address market = arrayStorage.elements[i];
                    IEulerMarket(market).hook(HOOK__MARKET_SUMMARY, transientMapping[market]);
                    delete transientMapping[market];
                }
                
                delete arrayStorage.elements[i];
                unchecked { ++i; }
            }

            delete transientArrays[arrayType];
        }
    }
}
