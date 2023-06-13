// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./TransientStorage.sol";
import "./Array.sol";

interface IEulerMarketRegistry {
    function isRegistered(address market) external returns (bool);
}

interface IEulerMarket {
    function checkLiquidity(address account, address[] memory collaterals) external view returns (bool isLiquid);
    function getHookBitmask() external view returns (uint bitmask);
    function hook(uint hookNumber, bytes memory data) external returns (bytes memory result);
}

interface IDeferredChecks {
    function onDeferredChecks(bytes memory data) external payable;
}


contract EulerConductor is TransientStorage {
    using Array for ArrayStorage;

    // Constants

    string public constant name = "Euler Conductor";

    uint internal constant HOOK__MARKET_FIRST_TOUCHED = 0;
    uint internal constant HOOK__MARKET_SUMMARY = 1;
    uint internal constant HOOK__ON_COLLATERAL_ADDED = 2;
    uint internal constant HOOK__ON_COLLATERAL_REMOVED = 3;
    uint internal constant HOOK__ON_LIABILITY_ADDED = 4;
    uint internal constant HOOK__ON_LIABILITY_REMOVED = 5;


    // Storage

    address public governorAdmin;
    address public eulerMarketRegistry;
    mapping(address => mapping(address => bool)) public accountOperators; // account => operator => isOperator

    mapping(address => ArrayStorage) internal accountCollaterals;
    mapping(address => ArrayStorage) internal accountLiabilities;


    // Events, Errors

    event Genesis();
    event ReferralCode(bytes32 indexed referralCode);
    event GovernorAdminSet(address indexed admin);
    event EulerMarketRegistrySet(address indexed registry);
    event AccountOperatorSet(address indexed account, address indexed operator);

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
            (uint160(msg.sender) | 0xFF) == (uint160(account) | 0xFF) || 
            accountOperators[account][msg.sender], 
            "e/not-authorized"
        );
        _;
    }

    modifier inDeferral {
        require(checksDeferred, "e/checks-not-deferred");
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
        bool isFirstTouched = !marketStatusChecks.arrayIncludes(market);
        uint bitmask;
        bytes memory data;

        if (isFirstTouched) {
            require(IEulerMarketRegistry(eulerMarketRegistry).isRegistered(market), "e/market-not-registered");

            try IEulerMarket(market).getHookBitmask() returns (uint _bitmask) {
                bitmask = _bitmask;
            } catch {}

            if ((bitmask & HOOK__MARKET_FIRST_TOUCHED) != 0) {
                data = IEulerMarket(market).hook(HOOK__MARKET_FIRST_TOUCHED, abi.encode(0));
            }

            if (checksDeferred) {
                marketStatusChecks.doAddElement(market);
                marketStatuses[market] = abi.encode(bitmask, data);
            }
        }

        _;

        if (!checksDeferred && (bitmask & HOOK__MARKET_SUMMARY) != 0) {
            IEulerMarket(market).hook(HOOK__MARKET_SUMMARY, data);
        }
    }

    modifier liquidityCheck(address account) {
        _;
        
        if (checksDeferred) liquidityDeferrals.doAddElement(account);
        else requireLiquidityInternal(account);
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


    // Account operators

    function setAccountOperator(address account, address newOperator) external {
        require((uint160(msg.sender) | 0xFF) == (uint160(account) | 0xFF), "e/not-authorized");

        accountOperators[account][newOperator] = true;
        emit AccountOperatorSet(account, newOperator);
    }


    // Collateral management

    function getCollateralMarkets(address account) external view notInDeferral returns (address[] memory) {
        return accountCollaterals[account].getArray();
    }

    function isCollateralMarketEnabled(address market, address account) external view notInDeferral returns (bool) {
        return accountCollaterals[account].arrayIncludes(market);
    }

    function enableCollateralMarket(address market, address account) external 
    marketStatusCheck(market) 
    ownerOrOperator(account) 
    liquidityCheck(account) {
        if (accountCollaterals[account].doAddElement(market)) {
            (uint bitmask,) = abi.decode(marketStatuses[market], (uint, bytes));

            if ((bitmask & HOOK__ON_COLLATERAL_ADDED) != 0) {
                IEulerMarket(market).hook(HOOK__ON_COLLATERAL_ADDED, abi.encode(account));
            }
        }
    }

    function disableCollateralMarket(address market, address account) external 
    marketStatusCheck(market) 
    ownerOrOperator(account) 
    liquidityCheck(account) {
        if (accountCollaterals[account].doRemoveElement(market)) {
            (uint bitmask,) = abi.decode(marketStatuses[market], (uint, bytes));

            if ((bitmask & HOOK__ON_COLLATERAL_REMOVED) != 0) {
                IEulerMarket(market).hook(HOOK__ON_COLLATERAL_REMOVED, abi.encode(account));
            }
        }
    }


    // Liability management

    function getLiabilityMarkets(address account) external view notInDeferral returns (address[] memory) {
        return accountLiabilities[account].getArray();
    }

    function isLiabilityMarketEnabled(address market, address account) external view returns (bool) {
        require(msg.sender == market || !checksDeferred, "e/checks-deferred");
        return accountLiabilities[account].arrayIncludes(market);
    }

    function enableLiabilityMarket(address market, address account) external 
    marketStatusCheck(market) 
    ownerOrOperator(account) 
    liquidityCheck(account) {
        if(accountLiabilities[account].doAddElement(market)) {
            (uint bitmask,) = abi.decode(marketStatuses[market], (uint, bytes));

            if ((bitmask & HOOK__ON_LIABILITY_ADDED) != 0) {
                IEulerMarket(market).hook(HOOK__ON_LIABILITY_ADDED, abi.encode(account));
            }
        }
    }

    function disableLiabilityMarket(address market, address account) external 
    marketStatusCheck(market) 
    marketOnly(market) 
    liquidityCheck(account) {
        if (accountLiabilities[account].doRemoveElement(market)) {
            (uint bitmask,) = abi.decode(marketStatuses[market], (uint, bytes));

            if ((bitmask & HOOK__ON_LIABILITY_REMOVED) != 0) {
                IEulerMarket(market).hook(HOOK__ON_LIABILITY_REMOVED, abi.encode(account));
            }
        }
    }


    // Batching

    function deferChecks(bytes memory data) external payable defer {
        IDeferredChecks(msg.sender).onDeferredChecks{value: msg.value}(data);
    }

    function batchDispatch(EulerBatch calldata batch) external payable registerReferralCode(batch.referralCode) defer
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
                (success, result) = executeInternal(targetContract, item.targetAccount, item.msgValue, item.data);
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

    function batchDispatchSimulate(EulerBatch calldata batch) external payable 
    returns (EulerBatchItemSimulationResult[] memory simulation) {
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

    function execute(address targetContract, address targetAccount, bytes calldata data) external payable
    returns (bool success, bytes memory result) {
        return executeInternal(targetContract, targetAccount, msg.value, data);
    }

    function forward(address targetContract, address targetAccount, bytes calldata data) external payable
    returns (bool success, bytes memory result) {
        return forwardInternal(targetContract, targetAccount, msg.value, data);
    }


    // Liquidity check

    function deferLiquidityCheck(address account) external inDeferral {
        liquidityDeferrals.doAddElement(account);
    }

    function checkLiquidity(address account) external view returns (bool isLiquid) {
        return checkLiquidityInternal(account);
    }



    // INTERNAL FUNCTIONS

    function executeInternal(address targetContract, address targetAccount, uint msgValue, bytes calldata data) internal
        marketStatusCheck(targetContract)
        ownerOrOperator(targetAccount)
        liquidityCheck(targetAccount)
        returns (bool success, bytes memory result)
    {
        require(targetContract != address(this), "e/invalid-target");
        
        return targetContract.call{value: msgValue}(abi.encodePacked(data, uint160(targetAccount), checksDeferred));

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

    function forwardInternal(address targetContract, address targetAccount, uint msgValue, bytes calldata data) internal
        marketStatusCheck(targetContract)
        liquidityCheck(targetAccount)
        returns (bool success, bytes memory result)
    {
        address[] memory liabilities = accountLiabilities[targetAccount].getArray();

        require(liabilities.length == 1 && liabilities[0] == msg.sender, "e/liability-not-in-control");
        require(accountCollaterals[targetAccount].arrayIncludes(targetContract), "e/collateral-not-enabled");

        return targetContract.call{value: msgValue}(abi.encodePacked(data, uint160(targetAccount), checksDeferred));

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
        address[] memory liabilities = accountLiabilities[account].getArray();
        
        if (liabilities.length == 0) return true;

        require(liabilities.length == 1, "e/borrow-isolation-violation");
        
        address[] memory collaterals = accountCollaterals[account].getArray();

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

        (, bytes memory data) = abi.decode(marketStatuses[firstElement], (uint, bytes));
        IEulerMarket(firstElement).hook(HOOK__MARKET_SUMMARY, data);
        delete marketStatuses[firstElement];
        
        for (uint i = 1; i < numElements;) {
            address market = marketStatusChecks.elements[i];
            (, data) = abi.decode(marketStatuses[market], (uint, bytes));

            IEulerMarket(market).hook(HOOK__MARKET_SUMMARY, data);
            
            delete marketStatuses[market];
            delete marketStatusChecks.elements[i];
            unchecked { ++i; }
        }

        delete marketStatusChecks;
    }


    // Error handling

    function revertBytes(bytes memory errMsg) internal pure {
        if (errMsg.length > 0) {
            assembly { revert(add(32, errMsg), mload(errMsg)) }
        }

        revert("e/empty-error");
    }
}
