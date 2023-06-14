// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./TransientStorage.sol";
import "./Array.sol";
import "forge-std/console.sol";

interface IEulerVaultRegistry {
    function isRegistered(address vault) external returns (bool);
}

interface IEulerVault {
    function checkAccountStatus(address account, address[] memory collaterals) external view returns (bool isValid);
    function hook(uint hookNumber, bytes memory data) external returns (bytes memory result);
    error VaultStatusViolation();
}

interface IDeferredChecks {
    function onDeferredChecks(bytes memory data) external payable;
}


contract EulerOrchestrator is TransientStorage {
    using Array for ArrayStorage;

    // Constants

    string public constant name = "Euler Orchestrator";

    uint internal constant HOOK__VAULT_SNAPSHOT = 0;
    uint internal constant HOOK__VAULT_FINISH = 1;


    // Storage

    address public governorAdmin;
    address public eulerVaultRegistry;
    mapping(address => mapping(address => bool)) public accountOperators; // account => operator => isOperator

    mapping(address => ArrayStorage) internal accountPerformers;
    mapping(address => ArrayStorage) internal accountConductors;


    // Events, Errors

    event Genesis();
    event GovernorAdminSet(address indexed admin);
    event EulerVaultRegistrySet(address indexed registry);
    event AccountOperatorSet(address indexed account, address indexed operator, bool isAuthorized);

    error NotAuthorized();
    error InvalidAddress();
    error DeferralViolation();
    error VaultNotRegistered(address vault);
    error AccountStatusViolation(address account);
    error VaultStatusViolation(address vault);
    error ConductorViolation(address account);
    error SimulationViolation();
    error SimulationResult(EulerBatchItemSimulationResult[] simulation);


    // Constructor

    constructor(address admin, address registry) {
        emit Genesis();

        governorAdmin = admin;
        eulerVaultRegistry = registry;
    }


    // Modifiers

    modifier governorOnly {
        if (msg.sender != governorAdmin) revert NotAuthorized();
        _;
    }

    modifier vaultOnly(address vault) {
        if (msg.sender != vault) revert NotAuthorized();
        _;
    }

    modifier ownerOrOperator(address account) {
        if ((uint160(msg.sender) | 0xFF) != (uint160(account) | 0xFF) && !accountOperators[account][msg.sender]) revert NotAuthorized();
        _;
    }

    modifier notInDeferral {
        if (checksDeferred) revert DeferralViolation();
        _;
    }

    modifier defer() {
        checksDeferred = true;

        _;

        checksDeferred = false;

        requireAccountStatusCheckAll();
        checkVaultStatusAll();

        assert(accountStatusChecks.numElements == 0);
        assert(vaultStatusChecks.numElements == 0);
    }

    modifier vaultStatusCheck(address vault) {
        bool isFirstTouched = !vaultStatusChecks.arrayIncludes(vault);
        bytes memory data;

        if (isFirstTouched && IEulerVaultRegistry(eulerVaultRegistry).isRegistered(vault)) {
            data = hookHandler(vault, HOOK__VAULT_SNAPSHOT, abi.encode(0));

            if (checksDeferred) {
                vaultStatusChecks.doAddElement(vault);
                vaultStatuses[vault] = data;
            }
        }

        _;

        if (!checksDeferred) hookHandler(vault, HOOK__VAULT_FINISH, data);
    }

    modifier accountStatusCheck(address account) {
        _;
        
        if (checksDeferred) accountStatusChecks.doAddElement(account);
        else requireAccountStatusCheckInternal(account);
    }


    // Governance

    function setGovernorAdmin(address newGovernorAdmin) external governorOnly {
        governorAdmin = newGovernorAdmin;
        emit GovernorAdminSet(newGovernorAdmin);
    }

    function setEulerVaultRegistry(address newEulerVaultRegistry) external governorOnly {
        if (newEulerVaultRegistry == address(0)) revert InvalidAddress();
        eulerVaultRegistry = newEulerVaultRegistry;
        emit EulerVaultRegistrySet(newEulerVaultRegistry);
    }


    // Account operators

    function setAccountOperator(address account, address operator, bool isAuthorized) external {
        if ((uint160(msg.sender) | 0xFF) != (uint160(account) | 0xFF)) revert NotAuthorized();
        else if ((uint160(msg.sender) | 0xFF) == (uint160(operator) | 0xFF)) revert InvalidAddress();

        accountOperators[account][operator] = isAuthorized;
        emit AccountOperatorSet(account, operator, isAuthorized);
    }


    // Performers management

    function getPerformers(address account) external view notInDeferral returns (address[] memory) {
        return accountPerformers[account].getArray();
    }

    function isPerformerEnabled(address vault, address account) external view notInDeferral returns (bool) {
        return accountPerformers[account].arrayIncludes(vault);
    }

    function enablePerformer(address vault, address account) public 
    ownerOrOperator(account) 
    accountStatusCheck(account) {
        if (!IEulerVaultRegistry(eulerVaultRegistry).isRegistered(vault)) revert VaultNotRegistered(vault);
        accountPerformers[account].doAddElement(vault);
    }

    function disablePerformer(address vault, address account) public 
    ownerOrOperator(account) 
    accountStatusCheck(account) {
        accountPerformers[account].doRemoveElement(vault);
    }


    // Conductors management

    function getConductors(address account) external view notInDeferral returns (address[] memory) {
        return accountConductors[account].getArray();
    }

    function isConductorEnabled(address vault, address account) external view returns (bool) {
        if (msg.sender != vault && checksDeferred) revert DeferralViolation();
        return accountConductors[account].arrayIncludes(vault);
    }

    function enableConductor(address vault, address account) public 
    ownerOrOperator(account) 
    accountStatusCheck(account) {
        if (!IEulerVaultRegistry(eulerVaultRegistry).isRegistered(vault)) revert VaultNotRegistered(vault);
        accountConductors[account].doAddElement(vault);
    }

    function disableConductor(address vault, address account) public 
    vaultOnly(vault) 
    accountStatusCheck(account) {
        accountConductors[account].doRemoveElement(vault);
    }


    // Batching

    function deferChecks(bytes memory data) public payable defer {
        IDeferredChecks(msg.sender).onDeferredChecks{value: msg.value}(data);
    }

    function batchDispatch(EulerBatchItem[] calldata items, bool isSimulation) public payable defer
    returns (EulerBatchItemSimulationResult[] memory simulation) {
        if (isSimulation) simulation = new EulerBatchItemSimulationResult[](items.length);

        for (uint i = 0; i < items.length;) {
            EulerBatchItem calldata item = items[i];
            address targetContract = item.targetContract;
            bool success;
            bytes memory result;

            if (targetContract == address(this)) {
                (success, result) = targetContract.delegatecall(item.data);
            } else {
                (success, result) = executeInternal(targetContract, item.targetAccount, item.msgValue, item.data);
            }

            if (isSimulation) {
                simulation[i].success = success;
                simulation[i].result = result;
            } else if (!(success || item.allowError)) {
                revertBytes(result);
            }

            unchecked { ++i; }
        }

        if (isSimulation) revert SimulationResult(simulation);
    }

    function batchDispatchSimulate(EulerBatchItem[] calldata items) public payable
    returns (EulerBatchItemSimulationResult[] memory simulation) {
        (bool success, bytes memory result) = address(this).delegatecall(
            abi.encodeWithSelector(
                this.batchDispatch.selector,
                items,
                true
            )
        );

        if (success) revert SimulationViolation();

        if(bytes4(result) == SimulationResult.selector){
            assembly { result := add(result, 4) }
            simulation = abi.decode(result, (EulerBatchItemSimulationResult[]));
        } else {
            revertBytes(result);
        }
    }


    // Call forwarding

    function execute(address targetContract, address targetAccount, bytes calldata data) public payable
    returns (bool success, bytes memory result) {
        return executeInternal(targetContract, targetAccount, msg.value, data);
    }

    function forward(address targetContract, address targetAccount, bytes calldata data) public payable
    returns (bool success, bytes memory result) {
        return forwardInternal(targetContract, targetAccount, msg.value, data);
    }


    // Account Status check

    function checkAccountStatus(address account) external view returns (bool isValid) {
        return checkAccountStatusInternal(account);
    }

    function checkAccountsStatus(address[] memory accounts) external view returns (bool[] memory isValid) {
        isValid = new bool[](accounts.length);
        for (uint i = 0; i < accounts.length;) {
            isValid[i] = checkAccountStatusInternal(accounts[i]);
            unchecked { ++i; }
        }
    }

    function requireAccountStatusCheck(address account) external {
        if (checksDeferred) accountStatusChecks.doAddElement(account);
        else requireAccountStatusCheckInternal(account);
    }

    function requireAccountsStatusCheck(address[] memory accounts) external {
        bool areChecksDeferred = checksDeferred;
        for (uint i = 0; i < accounts.length;) {
            if (areChecksDeferred) accountStatusChecks.doAddElement(accounts[i]);
            else requireAccountStatusCheckInternal(accounts[i]);
            unchecked { ++i; }
        }
    }


    // INTERNAL FUNCTIONS

    function executeInternal(address targetContract, address targetAccount, uint msgValue, bytes calldata data) internal
        vaultStatusCheck(targetContract)
        ownerOrOperator(targetAccount)
        accountStatusCheck(targetAccount)
        returns (bool success, bytes memory result)
    {
        if (targetContract == address(this)) revert InvalidAddress();
        
        return targetContract.call{value: msgValue}(abi.encodePacked(data, uint160(targetAccount), checksDeferred));

        // this function executes arbitrary calldata on a target contract.
        // if a target is a registered vault, the vault status is checked.
        // the function checks whether the msg.sender is authorized to act on behalf
        // of the targetAccount and account status check on that account is performed.

        // the target contract must check if the msg.sender is EulerConductor and if 
        // the trailing targetAccount address that is attached to the data is the 
        // the same as the account on which the operation will be performed (according 
        // to the calldata). if both conditions are met, it ensures that the msg.sender 
        // is authorized to act on behalf of the targetAccount.
        // additionally, if the trailing boolean flag is set, it means that
        // the account status check and vault status check (if applicable) are deferred.
    }

    function forwardInternal(address targetContract, address targetAccount, uint msgValue, bytes calldata data) internal
        vaultStatusCheck(targetContract)
        accountStatusCheck(targetAccount)
        returns (bool success, bytes memory result)
    {
        address[] memory conductors = accountConductors[targetAccount].getArray();

        if (conductors.length != 1) revert ConductorViolation(targetAccount);
        else if (conductors[0] != msg.sender || !accountPerformers[targetAccount].arrayIncludes(targetContract)) revert NotAuthorized();

        return targetContract.call{value: msgValue}(abi.encodePacked(data, uint160(targetAccount), checksDeferred));

        // this function executes arbitrary calldata on a target contract.
        // the function checks whether the msg.sender is authorized to call the target
        // by checking if the msg.sender is the only conductor of the targetAccount
        // (such a conductor vault is in control) and if the target is enabled as a performer.
        // the vault status is checked for the target contract as the target contract
        // is always a registered vault (otherwise it wouldn't be enabled as a performer). 
        // the account status check is always performed on the targetAccount.

        // this function helps the liquidation flow which may look as follows:
        // 1) liquidator enables the conductor vault to take over the liability
        // 2) liquidator calls liquidate() on the conductor vault
        //      if done from a batch, the vault should verify that the msg.sender is authorized 
        //      to act on behalf of the liquidator and that the checks are deferred (account status check
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


    // Account Status Check internals

    function checkAccountStatusInternal(address account) internal view returns (bool) {
        address[] memory conductors = accountConductors[account].getArray();
        
        if (conductors.length == 0) return true;
        else if (conductors.length > 1) revert ConductorViolation(account);
        
        address[] memory performers = accountPerformers[account].getArray();

        try IEulerVault(conductors[0]).checkAccountStatus(account, performers) returns (bool isValid) {
            return isValid;
        } catch {
            return false;
        }
    }

    function requireAccountStatusCheckInternal(address account) internal virtual {
        if (!checkAccountStatusInternal(account)) revert AccountStatusViolation(account);
    }

    function requireAccountStatusCheckAll() private {
        address firstElement = accountStatusChecks.firstElement;
        uint8 numElements = accountStatusChecks.numElements;

        if (numElements == 0) return;

        requireAccountStatusCheckInternal(firstElement);
        
        for (uint i = 1; i < numElements;) {
            requireAccountStatusCheckInternal(accountStatusChecks.elements[i]);
            
            delete accountStatusChecks.elements[i];
            unchecked { ++i; }
        }

        delete accountStatusChecks;
    }


    // Vault status check internals

    function checkVaultStatusAll() private {
        address firstElement = vaultStatusChecks.firstElement;
        uint8 numElements = vaultStatusChecks.numElements;

        if (numElements == 0) return;

        hookHandler(firstElement, HOOK__VAULT_FINISH, vaultStatuses[firstElement]);
        delete vaultStatuses[firstElement];
        
        for (uint i = 1; i < numElements;) {
            address vault = vaultStatusChecks.elements[i];

            hookHandler(vault, HOOK__VAULT_FINISH, vaultStatuses[vault]);
            delete vaultStatuses[vault];

            delete vaultStatusChecks.elements[i];
            unchecked { ++i; }
        }

        delete vaultStatusChecks;
    }


    // Hook handler

    function hookHandler(address vault, uint hookNumber, bytes memory data) internal returns (bytes memory result) {
        try IEulerVault(vault).hook(hookNumber, data) returns (bytes memory _result) {
            result = _result;
        } catch (bytes memory err) {
            if (bytes4(err) == IEulerVault.VaultStatusViolation.selector) revert VaultStatusViolation(vault);
        }
    }


    // Error handling

    function revertBytes(bytes memory errMsg) internal pure {
        if (errMsg.length > 0) {
            assembly { revert(add(32, errMsg), mload(errMsg)) }
        }

        revert("e/empty-error");
    }
}
