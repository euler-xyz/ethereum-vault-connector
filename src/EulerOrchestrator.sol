// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./TransientStorage.sol";
import "./Array.sol";

interface IEulerVaultRegistry {
    function isRegistered(address vault) external returns (bool);
}

interface IEulerVault {
    function checkLiquidity(address account, address[] memory collaterals) external view returns (bool isLiquid);
    function getHookBitmask() external view returns (uint bitmask);
    function hook(uint hookNumber, bytes memory data) external returns (bytes memory result);
}

interface IDeferredChecks {
    function onDeferredChecks(bytes memory data) external payable;
}


contract EulerOrchestrator is TransientStorage {
    using Array for ArrayStorage;

    // Constants

    string public constant name = "Euler Orchestrator";

    uint internal constant HOOK__VAULT_FIRST_TOUCHED = 0;
    uint internal constant HOOK__VAULT_SUMMARY = 1;


    // Storage

    address public governorAdmin;
    address public eulerVaultRegistry;
    mapping(address => mapping(address => bool)) public accountOperators; // account => operator => isOperator

    mapping(address => ArrayStorage) internal accountPerformers;
    mapping(address => ArrayStorage) internal accountConductors;


    // Events, Errors

    event Genesis();
    event ReferralCode(bytes32 indexed referralCode);
    event GovernorAdminSet(address indexed admin);
    event EulerVaultRegistrySet(address indexed registry);
    event AccountOperatorSet(address indexed account, address indexed operator);

    error BatchDispatchSimulation(EulerBatchItemSimulationResult[] simulation);


    // Constructor

    constructor(address admin, address registry) {
        emit Genesis();

        governorAdmin = admin;
        eulerVaultRegistry = registry;
    }


    // Modifiers

    modifier governorOnly {
        require(msg.sender == governorAdmin, "e/governor-only");
        _;
    }

    modifier vaultOnly(address vault) {
        require(msg.sender == vault, "e/vault-only");
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
        checkVaultStatusAll();

        assert(liquidityDeferrals.numElements == 0);
        assert(vaultStatusChecks.numElements == 0);
    }

    modifier vaultStatusCheck(address vault) {
        bool isFirstTouched = !vaultStatusChecks.arrayIncludes(vault);
        uint bitmask;
        bytes memory data;

        if (isFirstTouched && IEulerVaultRegistry(eulerVaultRegistry).isRegistered(vault)) {
            try IEulerVault(vault).getHookBitmask() returns (uint _bitmask) {
                bitmask = _bitmask;
            } catch {}

            if ((bitmask & HOOK__VAULT_FIRST_TOUCHED) != 0) {
                data = IEulerVault(vault).hook(HOOK__VAULT_FIRST_TOUCHED, abi.encode(0));
            }

            if (checksDeferred) {
                vaultStatusChecks.doAddElement(vault);
                vaultStatuses[vault] = abi.encode(bitmask, data);
            }
        }

        _;

        if (!checksDeferred && (bitmask & HOOK__VAULT_SUMMARY) != 0) {
            IEulerVault(vault).hook(HOOK__VAULT_SUMMARY, data);
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

    function setEulerVaultRegistry(address newEulerVaultRegistry) external governorOnly {
        require(newEulerVaultRegistry != address(0), "e/bad-registry-address");
        eulerVaultRegistry = newEulerVaultRegistry;
        emit EulerVaultRegistrySet(newEulerVaultRegistry);
    }


    // Account operators

    function setAccountOperator(address account, address newOperator) external {
        require((uint160(msg.sender) | 0xFF) == (uint160(account) | 0xFF), "e/not-authorized");

        accountOperators[account][newOperator] = true;
        emit AccountOperatorSet(account, newOperator);
    }


    // Performers management

    function getPerformers(address account) external view notInDeferral returns (address[] memory) {
        return accountPerformers[account].getArray();
    }

    function isPerformerEnabled(address vault, address account) external view notInDeferral returns (bool) {
        return accountPerformers[account].arrayIncludes(vault);
    }

    function enablePerformer(address vault, address account) external 
    ownerOrOperator(account) 
    liquidityCheck(account) {
        require(IEulerVaultRegistry(eulerVaultRegistry).isRegistered(vault), "e/vault-not-registered");
        accountPerformers[account].doAddElement(vault);
    }

    function disablePerformer(address vault, address account) external 
    ownerOrOperator(account) 
    liquidityCheck(account) {
        accountPerformers[account].doRemoveElement(vault);
    }


    // Conductors management

    function getConductors(address account) external view notInDeferral returns (address[] memory) {
        return accountConductors[account].getArray();
    }

    function isConductorEnabled(address vault, address account) external view returns (bool) {
        require(msg.sender == vault || !checksDeferred, "e/checks-deferred");
        return accountConductors[account].arrayIncludes(vault);
    }

    function enableConductor(address vault, address account) external 
    ownerOrOperator(account) 
    liquidityCheck(account) {
        require(IEulerVaultRegistry(eulerVaultRegistry).isRegistered(vault), "e/vault-not-registered");
        accountConductors[account].doAddElement(vault);
    }

    function disableConductor(address vault, address account) external 
    vaultOnly(vault) 
    liquidityCheck(account) {
        accountConductors[account].doRemoveElement(vault);
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
        vaultStatusCheck(targetContract)
        ownerOrOperator(targetAccount)
        liquidityCheck(targetAccount)
        returns (bool success, bytes memory result)
    {
        require(targetContract != address(this), "e/invalid-target");
        
        return targetContract.call{value: msgValue}(abi.encodePacked(data, uint160(targetAccount), checksDeferred));

        // this function executes arbitrary calldata on a target contract.
        // if a target is a registered vault, the vault status is checked.
        // the function checks whether the msg.sender is authorized to act on behalf
        // of the targetAccount and liquidity check on that account is performed.

        // the target contract must check if the msg.sender is EulerConductor and if 
        // the trailing targetAccount address that is attached to the data is the 
        // the same as the account on which the operation will be performed (according 
        // to the calldata). if both conditions are met, it ensures that the msg.sender 
        // is authorized to act on behalf of the targetAccount.
        // additionally, if the trailing boolean flag is set, it means that
        // the liquidity check and vault status check (if applicable) are deferred.
    }

    function forwardInternal(address targetContract, address targetAccount, uint msgValue, bytes calldata data) internal
        vaultStatusCheck(targetContract)
        liquidityCheck(targetAccount)
        returns (bool success, bytes memory result)
    {
        address[] memory conductors = accountConductors[targetAccount].getArray();

        require(conductors.length == 1 && conductors[0] == msg.sender, "e/conductor-not-in-control");
        require(accountPerformers[targetAccount].arrayIncludes(targetContract), "e/performer-not-enabled");

        return targetContract.call{value: msgValue}(abi.encodePacked(data, uint160(targetAccount), checksDeferred));

        // this function executes arbitrary calldata on a target contract.
        // the function checks whether the msg.sender is authorized to call the target
        // by checking if the msg.sender is the only conductor of the targetAccount
        // (such a conductor vault is in control) and if the target is enabled as a performer.
        // the vault status is checked for the target contract as the target contract
        // is always a registered vault (otherwise it wouldn't be enabled as a performer). 
        // the liquidity check is always performed on the targetAccount.

        // this function helps the liquidation flow which may look as follows:
        // 1) liquidator enables the conductor vault to take over the liability
        // 2) liquidator calls liquidate() on the conductor vault
        //      if done from a batch, the vault should verify that the msg.sender is authorized 
        //      to act on behalf of the liquidator and that the checks are deferred (liquidity check
        //      for a liquidator and vault status check for the conductor vault), as described 
        //      in executeInternal()
        // 3) conductor vault transfers the liability from the violator to the liquidator.
        //    it must be ensured that the liquidator had enabled the conductor before the liquidation
        // 4) conductor valut instructs the performer vault to give up violator's collateral.
        //    in order to do that, the conductor vault must use forward() function encoding 
        //    withdraw() action in the calldata to be fowarded. the forward() function should be 
        //    called as follows:
        //    EulerConductor.forward(performer vault, violator, data encoding collateral withdrawal from the violator)
    }


    // Liquidity check internals

    function checkLiquidityInternal(address account) internal view returns (bool) {
        address[] memory conductors = accountConductors[account].getArray();
        
        if (conductors.length == 0) return true;

        require(conductors.length == 1, "e/borrow-isolation-violation");
        
        address[] memory performers = accountPerformers[account].getArray();

        try IEulerVault(conductors[0]).checkLiquidity(account, performers) returns (bool isLiquid) {
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


    // Vault status check internals

    function checkVaultStatusAll() private {
        address firstElement = vaultStatusChecks.firstElement;
        uint8 numElements = vaultStatusChecks.numElements;

        if (numElements == 0) return;

        (uint bitmask, bytes memory data) = abi.decode(vaultStatuses[firstElement], (uint, bytes));

        if ((bitmask & HOOK__VAULT_SUMMARY) != 0) IEulerVault(firstElement).hook(HOOK__VAULT_SUMMARY, data);
        delete vaultStatuses[firstElement];
        
        for (uint i = 1; i < numElements;) {
            address vault = vaultStatusChecks.elements[i];
            (bitmask, data) = abi.decode(vaultStatuses[vault], (uint, bytes));

            if ((bitmask & HOOK__VAULT_SUMMARY) != 0) IEulerVault(vault).hook(HOOK__VAULT_SUMMARY, data);
            
            delete vaultStatuses[vault];
            delete vaultStatusChecks.elements[i];
            unchecked { ++i; }
        }

        delete vaultStatusChecks;
    }


    // Error handling

    function revertBytes(bytes memory errMsg) internal pure {
        if (errMsg.length > 0) {
            assembly { revert(add(32, errMsg), mload(errMsg)) }
        }

        revert("e/empty-error");
    }
}
