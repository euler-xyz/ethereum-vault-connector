// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./TransientStorage.sol";
import "./Array.sol";


interface IEulerVaultRegistry {
    function isRegistered(address vault) external returns (bool);
}

interface IEulerVault {
    function checkAccountStatus(address account, address[] memory collaterals) external view returns (bool isValid);
    function hook(uint hookNumber, bytes memory data) external returns (bytes memory result);
    error HookViolation(bytes data);
}


contract EulerConductor is TransientStorage {
    using Array for ArrayStorage;

    // Constants

    string public constant name = "Euler Conductor";

    uint internal constant HOOK__VAULT_SNAPSHOT = 0;
    uint internal constant HOOK__VAULT_FINISH = 1;


    // Storage

    address public governorAdmin;
    address public eulerVaultRegistry;
    mapping(address => mapping(address => bool)) public accountOperators; // account => operator => isOperator

    mapping(address => ArrayStorage) internal accountCollaterals;
    mapping(address => ArrayStorage) internal accountControllers;


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
    error VaultStatusViolation(address vault, bytes data);
    error ControllerViolation(address account);
    error SimulationViolation();
    error SimulationResult(EulerBatchItemSimulationResult[] simulation);


    // Constructor

    constructor(address admin, address registry) {
        emit Genesis();

        governorAdmin = admin;
        eulerVaultRegistry = registry;
    }


    // Modifiers

    /// @notice A modifier that allows only the governor admin to call the function.
    modifier governorOnly {
        if (msg.sender != governorAdmin) revert NotAuthorized();
        _;
    }

    /// @notice A modifier that allows only the specified vault account to call the function.
    /// @param vault The address of the vault that is allowed to call the function.
    modifier vaultOnly(address vault) {
        if (msg.sender != vault) revert NotAuthorized();
        _;
    }

    /// @notice A modifier that allows only the owner or an operator of the account to call the function.
    /// @dev The owner of an account is an address that matches first 19 bytes of the account address. An operator of an account is an address that has been authorized by the owner of an account to perform operations on behalf of the owner.
    /// @param account The address of the account for which it is checked whether msg.sender is the owner or an operator.
    modifier ownerOrOperator(address account) {
        if ((uint160(msg.sender) | 0xFF) != (uint160(account) | 0xFF) && !accountOperators[account][msg.sender]) revert NotAuthorized();
        _;
    }

    /// @notice A modifier that prevents the function from being called when the transaction is in checks deferral state.
    modifier notInDeferral {
        if (checksDeferred) revert DeferralViolation();
        _;
    }

    /// @notice A modifier that acts like a reentrancy guard on a batch, puts the batch transaction into checks deferral state and performs the account and vault checks at the end of the batch.
    /// @dev Transient storage must be cleared at the end of the batch.
    modifier defer() {
        if (checksDeferred) revert DeferralViolation();

        checksDeferred = true;

        _;

        checksDeferred = false;

        requireAccountStatusCheckAll();
        checkVaultStatusAll();

        assert(accountStatusChecks.numElements == 0);
        assert(vaultStatusChecks.numElements == 0);
    }

    /// @notice A modifier that checks the status of the specified address if it's registered as a vault.
    /// @dev Checks are performed only once per vault per transaction. First, the snapshot hook is called. If the checks are deferred, the vault is added to the list of the vaults to check at the end of the batch and the snapshot data is stored. If the checks are not deferred, the finish hook is called after the action is performed.
    /// @param vault The address of the vault to be checked.
    modifier vaultStatusCheck(address vault) {
        bytes memory data;

        if (!vaultStatusChecks.arrayIncludes(vault) && IEulerVaultRegistry(eulerVaultRegistry).isRegistered(vault)) {
            data = hookHandler(vault, HOOK__VAULT_SNAPSHOT, abi.encode(0));

            if (checksDeferred) {
                vaultStatusChecks.doAddElement(vault);
                vaultStatuses[vault] = data;
            }
        }

        _;

        if (!checksDeferred) hookHandler(vault, HOOK__VAULT_FINISH, data);
    }

    /// @notice A modifier that checks the status of the specified account.
    /// @dev Checks are performed only once per account per transaction. If the checks are deferred, the account is added to the list of the accounts to check at the end of the batch. If the checks are not deferred, the check is performed immediately after the action is performed.
    /// @param account The address of the account to be checked.
    modifier accountStatusCheck(address account) {
        _;
        
        if (checksDeferred) accountStatusChecks.doAddElement(account);
        else requireAccountStatusCheckInternal(account);
    }


    // Governance

    /// @notice Sets a new governor admin address.
    /// @dev Only the current governor can call this function.
    /// @param newGovernorAdmin The address of the new governor admin.
    function setGovernorAdmin(address newGovernorAdmin) external payable governorOnly {
        governorAdmin = newGovernorAdmin;
        emit GovernorAdminSet(newGovernorAdmin);
    }

    /// @notice Sets a new Euler vault registry address.
    /// @dev Only the current governor can call this function. The Euler vault registry is a contract that keeps track of all the vaults that are allowed to interact with the conductor.
    /// @param newEulerVaultRegistry The address of the new Euler vault registry.
    function setEulerVaultRegistry(address newEulerVaultRegistry) external payable governorOnly {
        if (newEulerVaultRegistry == address(0)) revert InvalidAddress();
        eulerVaultRegistry = newEulerVaultRegistry;
        emit EulerVaultRegistrySet(newEulerVaultRegistry);
    }


    // Account operators

    /// @notice Sets or unsets an operator for an account.
    /// @dev Only the owner of the account can call this function. An operator is an address that can perform actions for an account on behalf of the owner. 
    /// @param account The address of the account whose operator is being set or unset.
    /// @param operator The address of the operator that is being authorized or deauthorized.
    /// @param isAuthorized A boolean flag that indicates whether the operator is authorized or not.
    function setAccountOperator(address account, address operator, bool isAuthorized) external payable {
        if ((uint160(msg.sender) | 0xFF) != (uint160(account) | 0xFF)) revert NotAuthorized();
        else if ((uint160(msg.sender) | 0xFF) == (uint160(operator) | 0xFF)) revert InvalidAddress();

        accountOperators[account][operator] = isAuthorized;
        emit AccountOperatorSet(account, operator, isAuthorized);
    }


    // Collaterals management

    /// @notice Returns the array of collaterals for an account.
    /// @dev A collateral is a vault for which account's balances are under the control of the currently chosen controller vault. This function cannot be called when the transaction is in deferral state, as the collaterals may change during the transaction thus cannot be relied on within a batch.
    /// @param account The address of the account whose collaterals are being queried.
    /// @return An array of addresses that are the collaterals for the account.
    function getCollaterals(address account) external view notInDeferral returns (address[] memory) {
        return accountCollaterals[account].getArray();
    }

    /// @notice Returns whether a collateral is enabled for an account.
    /// @dev A collateral is a vault for which account's balances are under the control of the currently chosen controller vault. This function cannot be called when the transaction is in deferral state, as the collaterals may change during the transaction thus cannot be relied on within a batch.
    /// @param account The address of the account that is being checked.
    /// @param vault The address of the collateral that is being checked.
    /// @return A boolean value that indicates whether the vault is collateral for the account or not.
    function isCollateralEnabled(address account, address vault) external view notInDeferral returns (bool) {
        return accountCollaterals[account].arrayIncludes(vault);
    }

    /// @notice Enables a collateral for an account.
    /// @dev A collaterals is a vault for which account's balances are under the control of the currently chosen controller vault. Only the owner or an operator of the account can call this function and a vault must be registered to become a collateral. Account status checks are performed.
    /// @param account The address for which the collateral is being enabled.
    /// @param vault The address of the collateral being enabled.
    function enableCollateral(address account, address vault) public payable
    ownerOrOperator(account) 
    accountStatusCheck(account) {
        if (!IEulerVaultRegistry(eulerVaultRegistry).isRegistered(vault)) revert VaultNotRegistered(vault);
        accountCollaterals[account].doAddElement(vault);
    }

    /// @notice Disables a collateral for an account.
    /// @dev A collateral is a vault for which account’s balances are under the control of the currently chosen controller vault. Only the owner or an operator of the account can call this function. Account status checks are performed.
    /// @param account The address for which the collateral is being disabled.
    /// @param vault The address of the collateral being disabled. 
    function disableCollateral(address account, address vault) public payable
    ownerOrOperator(account) 
    accountStatusCheck(account) {
        accountCollaterals[account].doRemoveElement(vault);
    }


    // Controllers management

    /// @notice Returns the array of controllers for an account.
    /// @dev A controller is a vault that has been chosen for an account to have special control over account's balances in the collaterals vaults. A user can have multiple controllers during checks deferred state (within a batch), but only one (or none) can be selected when the account status check is made. This function cannot be called when the transaction is in deferral state, as the controllers may change during the transaction thus cannot be relied on within a batch.
    /// @param account The address of the account whose controllers are being queried.
    /// @return An array of addresses that are the controllers for the account.
    function getControllers(address account) external view notInDeferral returns (address[] memory) {
        return accountControllers[account].getArray();
    }

    /// @notice Returns whether a controller is enabled for an account.
    /// @dev A controller is a vault that has been chosen for an account to have special control over account’s balances in the collaterals vaults. If msg.sender is not a vault itself, this function cannot be called when the transaction is in deferral state, as the controllers may change during the transaction thus cannot be relied on within a batch.
    /// @param account The address of the account that is being checked.
    /// @param vault The address of the controller that is being checked.
    /// @return A boolean value that indicates whether the vault is controller for the account or not.
    function isControllerEnabled(address account, address vault) external view returns (bool) {
        if (msg.sender != vault && checksDeferred) revert DeferralViolation();
        return accountControllers[account].arrayIncludes(vault);
    }

    /// @notice Enables a controller for an account.
    /// @dev A controller is a vault that has been chosen for an account to have special control over account’s balances in the collaterals vaults. Only the owner or an operator of the account can call this function and a vault must be registered to become a controller. Account status checks are performed.
    /// @param account The address for which the controller is being enabled.
    /// @param vault The address of the controller being enabled. 
    function enableController(address account, address vault) public payable
    ownerOrOperator(account) 
    accountStatusCheck(account) {
        if (!IEulerVaultRegistry(eulerVaultRegistry).isRegistered(vault)) revert VaultNotRegistered(vault);
        accountControllers[account].doAddElement(vault);
    }

    /// @notice Disables a controller for an account.
    /// @dev A controller is a vault that has been chosen for an account to have special control over account’s balances in the collaterals vaults. Only the vault itself can call this function. Account status checks are performed.
    /// @param account The address for which the controller is being disabled.
    /// @param vault The address of the controller being disabled.
    function disableController(address account, address vault) public payable
    vaultOnly(vault) 
    accountStatusCheck(account) {
        accountControllers[account].doRemoveElement(vault);
    }


    // Batching


    /// @notice Defers the account and vault checks until the end of the transaction and executes a batch of batch items.
    /// @dev If isSimulation is true, the function always reverts and returns an array of simulation results is returned via SimulationResult error, otherwise it returns an empty array.
    /// @param items An array of batch items to be executed.
    /// @param isSimulation A boolean flag that indicates whether to simulate the results and revert or not.
    /// @return simulation Irrelevant. If isSimulation is true, the simulation result is returned via SimulationResult error, otherwise the array is empty.
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
                (success, result) = executeInternal(targetContract, item.onBehalfOfAccount, item.msgValue, item.data);
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

    /// @notice Simulates the execution of a batch of batch items and returns the simulation results.
    /// @param items An array of batch items to be simulated.
    /// @return simulation An array of simulation results for each batch item.
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

    /// @notice Executes a call to a target contract as per data encoded.
    /// @dev This function can be used to interact with any contract. If it is used to call a vault contract, the trailing data attached and the msg.sender can be used to check if msg.sender is authorized to act on behalf of the passed account and ensure that the account status check for the passed account and vault status check for the targetContract (if registered) are performed.
    /// @param targetContract The address of the contract to be called. If it is a registered vault, the vault status check is performed.
    /// @param onBehalfOfAccount The address of the account for which it is checked whether msg.sender is authorized to act on its behalf. Account status check is performed for this account.
    /// @param data The encoded data which is called on the target contract.
    /// @return success A boolean value that indicates whether the call succeeded or not.
    /// @return result Returned data from the call.
    function execute(address targetContract, address onBehalfOfAccount, bytes calldata data) public payable
    returns (bool success, bytes memory result) {
        return executeInternal(targetContract, onBehalfOfAccount, msg.value, data);
    }

    /// @notice Forwards a call to a target contract as per data encoded.
    /// @dev This function can be used to interact with any registered vault if it is enabled as a collateral of the onBehalfOfAccount and the caller is the only controller for the onBehalfOfAccount. The trailing data attached and the msg.sender can be used to check if msg.sender is authorized to act on behalf of the passed account and ensure that the account status check for the passed account and vault status check for targetContract are performed.
    /// @param targetContract The address of the contract to be called. It is always a registered vault thus the vault status check is performed.
    /// @param onBehalfOfAccount The address of the account for which it is checked whether msg.sender is authorized to act on its behalf. Account status check is performed for this account.
    /// @param data The encoded data which is called on the target contract.
    /// @return success A boolean value that indicates whether the call succeeded or not.
    /// @return result Returned data from the call. 
    function forward(address targetContract, address onBehalfOfAccount, bytes calldata data) public payable
    returns (bool success, bytes memory result) {
        return forwardInternal(targetContract, onBehalfOfAccount, msg.value, data);
    }


    // Account Status check

    /// @notice Checks the status of an account and returns whether it is valid or not.
    /// @dev Account status check is performed by calling into selected controller vault and passing the array of currently selected collaterals. If controller is not selected, the account is considered valid.
    /// @param account The address of the account to be checked.
    /// @return isValid A boolean value that indicates whether the account is valid or not.
    function checkAccountStatus(address account) external view returns (bool isValid) {
        return checkAccountStatusInternal(account);
    }

    /// @notice Checks the status of multiple accounts and returns an array of boolean values that indicate whether each account is valid or not. 
    /// @dev Account status check is performed by calling into selected controller vault and passing the array of currently selected collaterals. If controller is not selected, the account is considered valid.
    /// @param accounts An array of addresses of the accounts to be checked. 
    /// @return isValid An array of boolean values that indicate whether each account is valid or not.
    function checkAccountsStatus(address[] memory accounts) external view returns (bool[] memory isValid) {
        isValid = new bool[](accounts.length);
        for (uint i = 0; i < accounts.length;) {
            isValid[i] = checkAccountStatusInternal(accounts[i]);
            unchecked { ++i; }
        }
    }

    /// @notice Checks the status of an account and reverts if it is not valid.
    /// @dev If in the middle of checks deferral, the account is added to the array of accounts to be checked at the end of the batch. Account status check is performed by calling into selected controller vault and passing the array of currently selected collaterals. If controller is not selected, the account is considered valid.
    /// @param account The address of the account to be checked.
    function requireAccountStatusCheck(address account) external {
        if (checksDeferred) accountStatusChecks.doAddElement(account);
        else requireAccountStatusCheckInternal(account);
    }

    /// @notice Checks the status of multiple accounts and reverts if any of them is not valid.
    /// @dev If in the middle of checks deferral, the accounts are added to the array of accounts to be checked at the end of the batch. Account status check is performed by calling into selected controller vault and passing the array of currently selected collaterals. If controller is not selected, the account is considered valid.
    /// @param accounts An array of addresses of the accounts to be checked.
    function requireAccountsStatusCheck(address[] memory accounts) external {
        bool areChecksDeferred = checksDeferred;
        for (uint i = 0; i < accounts.length;) {
            if (areChecksDeferred) accountStatusChecks.doAddElement(accounts[i]);
            else requireAccountStatusCheckInternal(accounts[i]);
            unchecked { ++i; }
        }
    }


    // INTERNAL FUNCTIONS

    function executeInternal(address targetContract, address onBehalfOfAccount, uint msgValue, bytes calldata data) internal
        vaultStatusCheck(targetContract)
        ownerOrOperator(onBehalfOfAccount)
        accountStatusCheck(onBehalfOfAccount)   // TODO: decide if this is enforced here or it's the vault that decides for which accounts the status is checked
        returns (bool success, bytes memory result)
    {
        if (targetContract == address(this)) revert InvalidAddress();
        
        return targetContract.call{value: msgValue}(abi.encodePacked(data, uint160(onBehalfOfAccount), checksDeferred));
    }

    function forwardInternal(address targetContract, address onBehalfOfAccount, uint msgValue, bytes calldata data) internal
        vaultStatusCheck(targetContract)
        accountStatusCheck(onBehalfOfAccount)   // TODO: decide if this is enforced here or it's the vault that decides for which accounts the status is checked
        returns (bool success, bytes memory result)
    {
        address[] memory controllers = accountControllers[onBehalfOfAccount].getArray();

        if (controllers.length != 1) revert ControllerViolation(onBehalfOfAccount);
        else if (controllers[0] != msg.sender || !accountCollaterals[onBehalfOfAccount].arrayIncludes(targetContract)) revert NotAuthorized();

        return targetContract.call{value: msgValue}(abi.encodePacked(data, uint160(onBehalfOfAccount), checksDeferred));
    }


    // Account Status Check internals

    function checkAccountStatusInternal(address account) internal view returns (bool) {
        address[] memory controllers = accountControllers[account].getArray();
        
        if (controllers.length == 0) return true;
        else if (controllers.length > 1) revert ControllerViolation(account);
        
        address[] memory collaterals = accountCollaterals[account].getArray();

        try IEulerVault(controllers[0]).checkAccountStatus(account, collaterals) returns (bool isValid) {
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
            if (bytes4(err) == IEulerVault.HookViolation.selector) {
                assembly { err := add(err, 4) }
                revert VaultStatusViolation(vault, err);
            }
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
