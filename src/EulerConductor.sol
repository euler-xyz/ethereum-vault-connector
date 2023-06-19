// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./TransientStorage.sol";
import "./Types.sol";
import "./Array.sol";
import "forge-std/console.sol";


interface IEulerVaultRegistry {
    function isRegistered(address vault) external returns (bool);
}

interface IEulerVault {
    function checkAccountStatus(address account, address[] memory collaterals) external view returns (bool isValid);
    function hook(uint hookNumber, bytes memory data) external returns (bytes memory result);
    error HookViolation(bytes data);
}


contract EulerConductor is TransientStorage, Types {
    using Array for ArrayStorage;

    // Constants

    string public constant name = "Euler Conductor";

    uint8 internal constant CHECKS_DEFERRED__INIT = 1;
    uint8 internal constant CHECKS_DEFERRED__BUSY = 2;

    uint internal constant HOOK__VAULT_SNAPSHOT = 0;
    uint internal constant HOOK__VAULT_FINISH = 1;


    // Storage
    ExecutionContext internal executionContext;
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
    error RevertedBatchResult(EulerResult[] batchItemsResult, EulerResult[] accountsStatusResult, EulerResult[] vaultsStatusResult);
    error BatchPanic();


    // Constructor

    constructor(address admin, address registry) {
        emit Genesis();

        executionContext.checksDeferredState = CHECKS_DEFERRED__INIT;
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
        if (
            (uint160(msg.sender) | 0xFF) != (uint160(account) | 0xFF) && 
            !accountOperators[account][msg.sender]
        ) revert NotAuthorized();

        _;
    }

    /// @notice A modifier that prevents the function from being called when the transaction is in checks deferral state.
    modifier notInDeferral {
        if (executionContext.checksDeferredState != CHECKS_DEFERRED__INIT) revert DeferralViolation();
        _;
    }

    /// @notice A modifier that acts like a reentrancy guard on a batch, puts the batch transaction into checks deferral state.
    /// @dev Transient storage must be cleared at the end of the batch.
    modifier defer() {
        if (executionContext.checksDeferredState != CHECKS_DEFERRED__INIT) revert DeferralViolation();

        executionContext.checksDeferredState = CHECKS_DEFERRED__BUSY;

        _;

        executionContext.checksDeferredState = CHECKS_DEFERRED__INIT;

        assert(accountStatusChecks.numElements == 0);
        assert(vaultStatusChecks.numElements == 0);
    }

    /// @notice A modifier that checks the status of the specified address if it's registered as a vault.
    /// @dev Checks are performed only once per vault per transaction. First, the snapshot hook is called. If the checks are deferred, the vault is added to the list of the vaults to check at the end of the batch and the snapshot data is stored. If the checks are not deferred, the finish hook is called after the action is performed.
    /// @param vault The address of the vault to be checked.
    modifier vaultStatusCheck(address vault) {
        bool checksDeferred = executionContext.checksDeferredState != CHECKS_DEFERRED__INIT;
        bool isRegistered = IEulerVaultRegistry(eulerVaultRegistry).isRegistered(vault);
        bytes memory data;

        if (isRegistered && !vaultStatusChecks.arrayIncludes(vault)) {
            data = hookHandler(vault, HOOK__VAULT_SNAPSHOT, abi.encode(0));

            if (checksDeferred) {
                vaultStatusChecks.doAddElement(vault);
                vaultStatuses[vault] = data;
            } else vaultStatusViolationHandler(vault, data);
        }

        _;

        if (isRegistered && !checksDeferred) {
            data = hookHandler(vault, HOOK__VAULT_FINISH, data);
            vaultStatusViolationHandler(vault, data);
        }
    }

    /// @notice A modifier that checks the status of the specified account.
    /// @dev Checks are performed only once per account per transaction. If the checks are deferred, the account is added to the list of the accounts to check at the end of the batch. If the checks are not deferred, the check is performed immediately after the action is performed.
    /// @param account The address of the account to be checked.
    modifier accountStatusCheck(address account) {
        executionContext.onBehalfOfAccount = account;

        _;

        executionContext.onBehalfOfAccount = address(0);
        
        if (executionContext.checksDeferredState == CHECKS_DEFERRED__INIT) requireAccountStatusCheckInternal(account);
        else accountStatusChecks.doAddElement(account);
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
    function setAccountOperator(address account, address operator, bool isAuthorized) public payable {
        if ((uint160(msg.sender) | 0xFF) != (uint160(account) | 0xFF)) revert NotAuthorized();
        else if ((uint160(msg.sender) | 0xFF) == (uint160(operator) | 0xFF)) revert InvalidAddress();

        accountOperators[account][operator] = isAuthorized;
        emit AccountOperatorSet(account, operator, isAuthorized);
    }


    // Execution context

    /// @notice Returns the current execution context.
    /// @dev The execution context consists of checks deferral state and the account on behalf of which the transaction or current batch item is being executed.
    /// @return checksDeferred A boolean flag that indicates whether the checks are deferred or not.
    /// @return onBehalfOfAccount The address of the account on behalf of which the transaction or current batch item is being executed.
    function getExecutionContext() external view returns (bool checksDeferred, address onBehalfOfAccount) {
        ExecutionContext memory context = executionContext;
        checksDeferred = context.checksDeferredState != CHECKS_DEFERRED__INIT;
        onBehalfOfAccount = context.onBehalfOfAccount;
    }

    /// @notice Returns the current execution context extended with information whether a controller is enabled for an account.
    /// @dev The execution context consists of checks deferral state and the account on behalf of which the transaction or current batch item is being executed. If msg.sender is not a vault itself, this function cannot be called when the transaction is in checks deferral state, as the controllers may change during the transaction thus cannot be relied on within a batch.
    /// @param account The address of the account for which controller is being checked.
    /// @param vault The address of the controller that is being checked.
    /// @return checksDeferred A boolean flag that indicates whether the checks are deferred or not.
    /// @return onBehalfOfAccount The address of the account on behalf of which the transaction or current batch item is being executed.
    /// @return controllerEnabled A boolean value that indicates whether the vault is controller for the account or not.
    function getExecutionContextExtended(address account, address vault) external view 
    returns (bool checksDeferred, address onBehalfOfAccount, bool controllerEnabled) {
        ExecutionContext memory context = executionContext;
        checksDeferred = context.checksDeferredState != CHECKS_DEFERRED__INIT;

        if (msg.sender != vault && checksDeferred) revert DeferralViolation();

        onBehalfOfAccount = context.onBehalfOfAccount;
        controllerEnabled = accountControllers[account].arrayIncludes(vault);
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
    function enableCollateral(address account, address vault) public payable virtual
    ownerOrOperator(account) 
    accountStatusCheck(account) {
        if (!IEulerVaultRegistry(eulerVaultRegistry).isRegistered(vault)) revert VaultNotRegistered(vault);
        accountCollaterals[account].doAddElement(vault);
    }

    /// @notice Disables a collateral for an account.
    /// @dev A collateral is a vault for which account’s balances are under the control of the currently chosen controller vault. Only the owner or an operator of the account can call this function. Account status checks are performed.
    /// @param account The address for which the collateral is being disabled.
    /// @param vault The address of the collateral being disabled. 
    function disableCollateral(address account, address vault) public payable virtual
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
        if (msg.sender != vault && executionContext.checksDeferredState != CHECKS_DEFERRED__INIT) revert DeferralViolation();
        return accountControllers[account].arrayIncludes(vault);
    }

    /// @notice Enables a controller for an account.
    /// @dev A controller is a vault that has been chosen for an account to have special control over account’s balances in the collaterals vaults. Only the owner or an operator of the account can call this function and a vault must be registered to become a controller. Account status checks are performed.
    /// @param account The address for which the controller is being enabled.
    /// @param vault The address of the controller being enabled. 
    function enableController(address account, address vault) public payable virtual
    ownerOrOperator(account) 
    accountStatusCheck(account) {
        if (!IEulerVaultRegistry(eulerVaultRegistry).isRegistered(vault)) revert VaultNotRegistered(vault);
        accountControllers[account].doAddElement(vault);
    }

    /// @notice Disables a controller for an account.
    /// @dev A controller is a vault that has been chosen for an account to have special control over account’s balances in the collaterals vaults. Only the vault itself can call this function. Account status checks are performed.
    /// @param account The address for which the controller is being disabled.
    /// @param vault The address of the controller being disabled.
    function disableController(address account, address vault) public payable virtual
    vaultOnly(vault) 
    accountStatusCheck(account) {
        accountControllers[account].doRemoveElement(vault);
    }


    // Batching


    /// @notice Defers the account and vault checks until the end of the transaction and executes a batch of batch items.
    /// @dev Accounts status checks and vault status checks are performed after all the batch items have been executed.
    /// @param items An array of batch items to be executed.
    function batch(EulerBatchItem[] calldata items) public payable virtual defer {
        batchInternal(items, false);
        checkAccountStatusAll(false);
        checkVaultStatusAll(false);
    }

    /// @notice Defers the account and vault checks until the end of the transaction and executes a batch of batch items.
    /// @dev This function always reverts as it's only used for simulation purposes. Accounts status checks and vault status checks are performed after all the batch items have been executed.
    /// @param items An array of batch items to be executed.
    /// @return batchItemsResult An array of batch item results for each item.
    /// @return accountsStatusResult An array of account status results for each account.
    /// @return vaultsStatusResult An array of vault status results for each vault.
    function batchRevert(EulerBatchItem[] calldata items) public virtual defer
    returns (EulerResult[] memory batchItemsResult, EulerResult[] memory accountsStatusResult, EulerResult[] memory vaultsStatusResult) {
        batchItemsResult = batchInternal(items, true);
        accountsStatusResult= checkAccountStatusAll(true);
        vaultsStatusResult= checkVaultStatusAll(true);

        revert RevertedBatchResult(batchItemsResult, accountsStatusResult, vaultsStatusResult);
    }

    function batchSimulation(EulerBatchItem[] calldata items) public payable virtual defer
    returns (EulerResult[] memory batchItemsResult, EulerResult[] memory accountsStatusResult, EulerResult[] memory vaultsStatusResult) {        
        (bool success, bytes memory result) = address(this).delegatecall(
            abi.encodeWithSelector(
                this.batchRevert.selector,
                items
            )
        );

        if (success) revert BatchPanic();
        else if(bytes4(result) != RevertedBatchResult.selector) revertBytes(result);

        assembly { result := add(result, 4) }
        (batchItemsResult, accountsStatusResult, vaultsStatusResult) = abi.decode(
            result,
            (EulerResult[], EulerResult[], EulerResult[])
        );
    }


    // Call forwarding

    /// @notice Executes a call to a target contract as per data encoded.
    /// @dev This function can be used to interact with any contract.
    /// @param targetContract The address of the contract to be called. If it is a registered vault, the vault status check is performed.
    /// @param onBehalfOfAccount The address of the account for which it is checked whether msg.sender is authorized to act on its behalf. Account status check is performed for this account.
    /// @param data The encoded data which is called on the target contract.
    /// @return success A boolean value that indicates whether the call succeeded or not.
    /// @return result Returned data from the call.
    function execute(address targetContract, address onBehalfOfAccount, bytes calldata data) public payable virtual
    returns (bool success, bytes memory result) {
        (success, result) = executeInternal(targetContract, onBehalfOfAccount, msg.value, data);
    }

    /// @notice Forwards a call to a target contract as per data encoded.
    /// @dev This function can be used to interact with any registered vault if it is enabled as a collateral of the onBehalfOfAccount and the caller is the only controller for the onBehalfOfAccount.
    /// @param targetContract The address of the contract to be called. It is always a registered vault thus the vault status check is performed.
    /// @param onBehalfOfAccount The address of the account for which it is checked whether msg.sender is authorized to act on its behalf. Account status check is performed for this account.
    /// @param data The encoded data which is called on the target contract.
    /// @return success A boolean value that indicates whether the call succeeded or not.
    /// @return result Returned data from the call. 
    function forward(address targetContract, address onBehalfOfAccount, bytes calldata data) public payable virtual
    returns (bool success, bytes memory result) {
        (success, result) = forwardInternal(targetContract, onBehalfOfAccount, msg.value, data);
    }


    // Account Status check

    /// @notice Checks the status of an account and returns whether it is valid or not.
    /// @dev Account status check is performed by calling into selected controller vault and passing the array of currently selected collaterals. If controller is not selected, the account is considered valid.
    /// @param account The address of the account to be checked.
    /// @return isValid A boolean value that indicates whether the account is valid or not.
    function checkAccountStatus(address account) public view returns (bool isValid) {
        return checkAccountStatusInternal(account);
    }

    /// @notice Checks the status of multiple accounts and returns an array of boolean values that indicate whether each account is valid or not. 
    /// @dev Account status check is performed by calling into selected controller vault and passing the array of currently selected collaterals. If controller is not selected, the account is considered valid.
    /// @param accounts An array of addresses of the accounts to be checked. 
    /// @return isValid An array of boolean values that indicate whether each account is valid or not.
    function checkAccountsStatus(address[] memory accounts) public view returns (bool[] memory isValid) {
        isValid = new bool[](accounts.length);
        for (uint i = 0; i < accounts.length;) {
            isValid[i] = checkAccountStatusInternal(accounts[i]);
            unchecked { ++i; }
        }
    }

    /// @notice Checks the status of an account and reverts if it is not valid.
    /// @dev If in the middle of checks deferral, the account is added to the array of accounts to be checked at the end of the batch. Account status check is performed by calling into selected controller vault and passing the array of currently selected collaterals. If controller is not selected, the account is considered valid.
    /// @param account The address of the account to be checked.
    function requireAccountStatusCheck(address account) public {
        if (executionContext.checksDeferredState == CHECKS_DEFERRED__INIT) requireAccountStatusCheckInternal(account);
        else accountStatusChecks.doAddElement(account);
    }

    /// @notice Checks the status of multiple accounts and reverts if any of them is not valid.
    /// @dev If in the middle of checks deferral, the accounts are added to the array of accounts to be checked at the end of the batch. Account status check is performed by calling into selected controller vault and passing the array of currently selected collaterals. If controller is not selected, the account is considered valid.
    /// @param accounts An array of addresses of the accounts to be checked.
    function requireAccountsStatusCheck(address[] memory accounts) public {
        bool checksDeferred = executionContext.checksDeferredState != CHECKS_DEFERRED__INIT;
        for (uint i = 0; i < accounts.length;) {
            if (checksDeferred) accountStatusChecks.doAddElement(accounts[i]);
            else requireAccountStatusCheckInternal(accounts[i]);
            unchecked { ++i; }
        }
    }


    // INTERNAL FUNCTIONS

    function batchInternal(EulerBatchItem[] calldata items, bool returnResult) internal 
    returns (EulerResult[] memory batchItemsResult) {
        if (returnResult) batchItemsResult = new EulerResult[](items.length);

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

            if (returnResult) {
                batchItemsResult[i].success = success;
                batchItemsResult[i].result = result;
            } else if (!(success || item.allowError)) revertBytes(result);

            unchecked { ++i; }
        }
    }

    function executeInternal(address targetContract, address onBehalfOfAccount, uint msgValue, bytes calldata data) internal
    vaultStatusCheck(targetContract)
    ownerOrOperator(onBehalfOfAccount)
    accountStatusCheck(onBehalfOfAccount)   // TODO: decide if this is enforced here or it's the vault that decides for which accounts the status is checked
    returns (bool success, bytes memory result) {
        if (targetContract == address(this)) revert InvalidAddress();
        
        (success, result) = targetContract.call{value: msgValue}(data);
    }

    function forwardInternal(address targetContract, address onBehalfOfAccount, uint msgValue, bytes calldata data) internal
    vaultStatusCheck(targetContract)
    accountStatusCheck(onBehalfOfAccount)   // TODO: decide if this is enforced here or it's the vault that decides for which accounts the status is checked
    returns (bool success, bytes memory result) {
        address[] memory controllers = accountControllers[onBehalfOfAccount].getArray();

        if (controllers.length != 1) revert ControllerViolation(onBehalfOfAccount);
        else if (controllers[0] != msg.sender || !accountCollaterals[onBehalfOfAccount].arrayIncludes(targetContract)) revert NotAuthorized();

        (success, result) = targetContract.call{value: msgValue}(data);
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

    function checkAccountStatusAll(bool returnResult) private returns (EulerResult[] memory result) {
        address firstElement = accountStatusChecks.firstElement;
        uint8 numElements = accountStatusChecks.numElements;

        if (returnResult) result = new EulerResult[](numElements);

        if (numElements == 0) return result;

        address account = firstElement;

        if (returnResult) {
            if (checkAccountStatusInternal(account)) result[0].success = true;
            else {
                result[0].success = false;
                result[0].result = abi.encodeWithSelector(
                    AccountStatusViolation.selector,
                    account
                );
            }
        } else requireAccountStatusCheckInternal(account);
        
        for (uint i = 1; i < numElements;) {
            account = accountStatusChecks.elements[i];

            if (returnResult) {
                if (checkAccountStatusInternal(account)) result[i].success = true;
                else {
                    result[i].success = false;
                    result[i].result = abi.encodeWithSelector(
                        AccountStatusViolation.selector,
                        account
                    );
                }
            } else requireAccountStatusCheckInternal(account);
            
            delete accountStatusChecks.elements[i];
            unchecked { ++i; }
        }

        delete accountStatusChecks;
    }


    // Vault status check internals

    function checkVaultStatusAll(bool returnResult) private returns (EulerResult[] memory result) {
        address firstElement = vaultStatusChecks.firstElement;
        uint8 numElements = vaultStatusChecks.numElements;
        
        if (returnResult) result = new EulerResult[](numElements);

        if (numElements == 0) return result;

        address vault = firstElement;
        bytes memory data = vaultStatuses[vault];

        if (returnResult) {
            if (bytes4(data) == IEulerVault.HookViolation.selector) result[0].success = false;
            else {
                data = hookHandler(vault, HOOK__VAULT_FINISH, data);

                if (bytes4(data) == IEulerVault.HookViolation.selector) result[0].success = false;
                else result[0].success = true;
            }
            result[0].result = data;
        } else {
            vaultStatusViolationHandler(vault, data);
            data = hookHandler(vault, HOOK__VAULT_FINISH, data);
            vaultStatusViolationHandler(vault, data);
        }

        delete vaultStatuses[firstElement];
        
        for (uint i = 1; i < numElements;) {
            vault = vaultStatusChecks.elements[i];
            data = vaultStatuses[vault];

            if (returnResult) {
                if (bytes4(data) == IEulerVault.HookViolation.selector) result[i].success = false;
                else {
                    data = hookHandler(vault, HOOK__VAULT_FINISH, data);

                    if (bytes4(data) == IEulerVault.HookViolation.selector) result[i].success = false;
                    else result[i].success = true;
                }
                result[i].result = data;
            } else {
                vaultStatusViolationHandler(vault, data);
                data = hookHandler(vault, HOOK__VAULT_FINISH, data);
                vaultStatusViolationHandler(vault, data);
            }

            delete vaultStatuses[vault];
            delete vaultStatusChecks.elements[i];
            unchecked { ++i; }
        }

        delete vaultStatusChecks;
    }


    // Hook handler

    function hookHandler(address vault, uint hookNumber, bytes memory data) private returns (bytes memory result) {
        try IEulerVault(vault).hook(hookNumber, data) returns (bytes memory res) {
            result = res;
        } catch (bytes memory err) {
            result = err;
        }
    }

    function vaultStatusViolationHandler(address vault, bytes memory data) private pure {
        if (bytes4(data) == IEulerVault.HookViolation.selector) revert VaultStatusViolation(vault, data);
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
