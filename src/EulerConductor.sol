// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./TransientStorage.sol";

interface IEulerMarketRegistry {
    function isRegistered(address market) external returns (bool);
}

interface IEulerMarket {
    function checkLiquidity(address account, address[] memory collaterals) external view returns (bool isLiquid);
    function hook(uint hookNumber, bytes memory data) external returns (bytes memory result);
}

interface IDeferredChecks {
    function onDeferredChecks(bytes memory data) external;
}


contract EulerConductor is TransientStorage {
    // Constants

    string public constant name = "Euler Conductor";

    uint internal constant HOOK__DISABLE_LIABILITY_MARKET = 0;
    uint internal constant HOOK__MARKET_FIRST_TOUCHED = 1;
    uint internal constant HOOK__MARKET_SUMMARY = 2;


    // Storage 

    address public governorAdmin;
    address public eulerMarketRegistry;

    mapping(address => address) public accountOperators;
    mapping(address => ArrayStorage) internal accountCollaterals;
    mapping(address => ArrayStorage) internal accountLiabilities;

    address[] internal activeMarkets;
    mapping(address => bool) internal isActive;


    // Events, Errors

    event Genesis();
    event MarketActivated(address indexed market, address indexed marketCreator);

    event GovernorAdminSet(address indexed admin);
    event EulerMarketRegistrySet(address indexed registry);
    event AccountOperatorSet(address indexed account, address operator);
    
    event ReferralCode(bytes32 indexed referralCode);

    error BatchDispatchSimulation(EulerBatchItemSimulationResult[] simulation);


    // Constructor

    constructor(address admin, address registry) {
        emit Genesis();

        governorAdmin = admin;
        eulerMarketRegistry = registry;
    }


    // Modifiers

    modifier governorOnly {
        require(msg.sender == governorAdmin, "e/governor-only");
        _;
    }

    modifier marketOnly(address market) {
        require(msg.sender == market, "e/market-only");
        _;
    }

    modifier ownerOrOperator(address account) {
        require(
            ((uint160(msg.sender) | 0xFF) == (uint160(account) | 0xFF)) || msg.sender == accountOperators[account],
            "e/account-operator-only"
        );
        
        _;
    }

    modifier notInDeferral {
        require(!checksDeferred, "e/checks-deferred");
        _;
    }

    modifier defer() {
        checksDeferred = true;

        _;

        checksDeferred = false;

        requireLiquidityAll();
        checkMarketStatusAll();

        assert(liquidityDeferrals.numElements == 0);
        assert(marketStatusChecks.numElements == 0);
    }

    modifier marketStatusCheck(address market) {
        // skip the hooks if the address is not an active market
        if (!isActive[market]) {
            _;
            return;
        }

        bytes memory data;
        if (!arrayIncludes(marketStatusChecks, market)) {
            data = IEulerMarket(market).hook(HOOK__MARKET_FIRST_TOUCHED, abi.encode(0));
        }

        _;

        if (!checksDeferred) {
            IEulerMarket(market).hook(HOOK__MARKET_SUMMARY, data);
        } else if (!arrayIncludes(marketStatusChecks, market)) {
            doAddElement(marketStatusChecks, market);
            marketStatuses[market] = data;
        }
    }

    modifier liquidityCheck(address account) {
        _;
        
        if (!checksDeferred) {
            requireLiquidityInternal(account);
        } else if (!arrayIncludes(liquidityDeferrals, account)) {
            doAddElement(liquidityDeferrals, account);
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

    function activateMarket(address market) external {
        require(market != address(this), "e/invalid-market");
        require(!isActive[market], "e/market-already-activated");
        require(IEulerMarketRegistry(eulerMarketRegistry).isRegistered(market), "e/market-not-registred");

        isActive[market] = true;
        activeMarkets.push(market);

        // assure that the market is implemented correctly
        IEulerMarket(market).hook(HOOK__DISABLE_LIABILITY_MARKET, abi.encode(msg.sender));
        IEulerMarket(market).hook(
            HOOK__MARKET_SUMMARY, 
            IEulerMarket(market).hook(HOOK__MARKET_FIRST_TOUCHED, abi.encode(0))
        );

        address[] memory collaterals = new address[](0);
        require(IEulerMarket(market).checkLiquidity(msg.sender, collaterals), "e/dry-liquidity-check-invalid");

        emit MarketActivated(market, msg.sender);
    }

    function isMarketActive(address market) external view notInDeferral returns (bool) {
        return isActive[market];
    }

    function getActiveMarkets() external view notInDeferral returns (address[] memory) {
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

    function getCollateralMarkets(address account) external view notInDeferral returns (address[] memory) {
        return getArray(accountCollaterals[account]);
    }

    function isCollateralMarketEnabled(address market, address account) external view notInDeferral returns (bool) {
        return arrayIncludes(accountCollaterals[account], market);
    }

    function enableCollateralMarket(address market, address account) external ownerOrOperator(account) liquidityCheck(account) {
        require(isActive[market], "e/market-not-activated");
        doAddElement(accountCollaterals[account], market);
    }

    function disableCollateralMarket(address market, address account) external ownerOrOperator(account) liquidityCheck(account) {
        doRemoveElement(accountCollaterals[account], market);
    }


    // Liability management

    function getLiabilityMarkets(address account) external view notInDeferral returns (address[] memory) {
        return getArray(accountLiabilities[account]);
    }

    function isLiabilityMarketEnabled(address market, address account) external view returns (bool) {
        require(msg.sender == market || !checksDeferred, "e/checks-deferred");
        return arrayIncludes(accountLiabilities[account], market);
    }

    function enableLiabilityMarket(address market, address account) external ownerOrOperator(account) liquidityCheck(account) {
        require(isActive[market], "e/market-not-activated");
        doAddElement(accountLiabilities[account], market);
    }

    function disableLiabilityMarket(address market, address account) external marketOnly(market) liquidityCheck(account) {
        doRemoveElement(accountLiabilities[account], market);
    }


    // Batching

    function deferChecks(bytes memory data) external defer {
        IDeferredChecks(msg.sender).onDeferredChecks(data);
    }

    function batchDispatch(EulerBatch calldata batch) external registerReferralCode(batch.referralCode) defer
    returns (EulerBatchItemSimulationResult[] memory simulation) {
        if (batch.isSimulation) simulation = new EulerBatchItemSimulationResult[](batch.items.length);

        for (uint i = 0; i < batch.items.length;) {
            EulerBatchItem calldata item = batch.items[i];
            address targetContract = item.targetContract;
            bool success;
            bytes memory result;

            if (targetContract == address(this)) {
                (success, result) = targetContract.delegatecall(item.data);
            } else {
                (success, result) = executeInternal(targetContract, item.targetAccount, item.data);
            }

            if (batch.isSimulation) {
                simulation[i].success = success;
                simulation[i].result = result;
            } else if (!(success || item.allowError)) {
                revertBytes(result);
            }

            unchecked { ++i; }
        }

        if (batch.isSimulation) revert BatchDispatchSimulation(simulation);
    }

    function batchDispatchSimulate(EulerBatch calldata batch) external returns (EulerBatchItemSimulationResult[] memory simulation) {
        (bool success, bytes memory result) = address(this).delegatecall(
            abi.encodeWithSelector(
                this.batchDispatch.selector,
                batch
            )
        );

        if (success) revert("e/simulation-did-not-revert");

        if(bytes4(result) == BatchDispatchSimulation.selector){
            assembly { result := add(result, 4) }
            simulation = abi.decode(result, (EulerBatchItemSimulationResult[]));
        } else {
            revertBytes(result);
        }
    }


    // Call forwarding

    function execute(address targetContract, address targetAccount, bytes calldata data) external 
    returns (bool success, bytes memory result) {
        return executeInternal(targetContract, targetAccount, data);
    }

    function forward(address targetContract, address targetAccount, bytes calldata data) external 
    returns (bool success, bytes memory result) {
        return forwardInternal(targetContract, targetAccount, data);
    }


    // Liquidity check

    function checkLiquidity(address account) external view returns (bool isLiquid) {
        return checkLiquidityInternal(account);
    }



    // INTERNAL FUNCTIONS

    function executeInternal(address targetContract, address targetAccount, bytes calldata data) internal
        marketStatusCheck(targetContract)
        ownerOrOperator(targetAccount)
        liquidityCheck(targetAccount)
        returns (bool success, bytes memory result)
    {
        require(targetContract != address(this), "e/invalid-target");
        
        return targetContract.call(abi.encodePacked(data, uint160(targetAccount), checksDeferred));

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
        marketStatusCheck(targetContract)
        liquidityCheck(targetAccount)
        returns (bool success, bytes memory result)
    {
        address[] memory liabilities = getArray(accountLiabilities[targetAccount]);

        require(liabilities.length == 1 && liabilities[0] == msg.sender, "e/liability-not-in-control");
        require(arrayIncludes(accountCollaterals[targetAccount], targetContract), "e/collateral-not-enabled");

        return targetContract.call(abi.encodePacked(data, uint160(targetAccount), checksDeferred));

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

    function checkLiquidityInternal(address account) internal view returns (bool) {
        address[] memory liabilities = getArray(accountLiabilities[account]);
        
        if (liabilities.length == 0) return true;

        require(liabilities.length == 1, "e/borrow-isolation-violation");
        
        address[] memory collaterals = getArray(accountCollaterals[account]);

        try IEulerMarket(liabilities[0]).checkLiquidity(account, collaterals) returns (bool isLiquid) {
            return isLiquid;
        } catch {
            return false;
        }
    }

    function requireLiquidityInternal(address account) internal view {
        require(checkLiquidityInternal(account), "e/collateral-violation");
    }

    function requireLiquidityAll() private {
        address firstElement = liquidityDeferrals.firstElement;
        uint8 numElements = liquidityDeferrals.numElements;

        if (numElements == 0) return;

        requireLiquidityInternal(firstElement);
        
        for (uint i = 1; i < numElements;) {
            requireLiquidityInternal(liquidityDeferrals.elements[i]);
            
            delete liquidityDeferrals.elements[i];
            unchecked { ++i; }
        }

        delete liquidityDeferrals;
    }


    // Market status check internals

    function checkMarketStatusAll() private {
        address firstElement = marketStatusChecks.firstElement;
        uint8 numElements = marketStatusChecks.numElements;

        if (numElements == 0) return;

        IEulerMarket(firstElement).hook(HOOK__MARKET_SUMMARY, marketStatuses[firstElement]);
        delete marketStatuses[firstElement];
        
        for (uint i = 1; i < numElements;) {
            address market = marketStatusChecks.elements[i];

            IEulerMarket(market).hook(HOOK__MARKET_SUMMARY, marketStatuses[market]);
            delete marketStatuses[market];
            
            delete marketStatusChecks.elements[i];
            unchecked { ++i; }
        }

        delete marketStatusChecks;
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

        if (numElements == 0) return; // already removed

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

            if (searchIndex == type(uint).max) return; // already removed
        }

        uint lastMarketIndex = numElements - 1;

        if (searchIndex != lastMarketIndex) {
            if (searchIndex == 0) arrayStorage.firstElement = arrayStorage.elements[lastMarketIndex];
            else arrayStorage.elements[searchIndex] = arrayStorage.elements[lastMarketIndex];
        }

        arrayStorage.numElements = uint8(lastMarketIndex);

        if (lastMarketIndex != 0) delete arrayStorage.elements[lastMarketIndex];
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


    // Error handling

    function revertBytes(bytes memory errMsg) internal pure {
        if (errMsg.length > 0) {
            assembly {
                revert(add(32, errMsg), mload(errMsg))
            }
        }

        revert("e/empty-error");
    }
}
