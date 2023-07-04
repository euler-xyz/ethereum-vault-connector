// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./TransientStorage.sol";
import "./Types.sol";
import "./Set.sol";
import "./interfaces/ICreditVaultProtocol.sol";
import "./interfaces/ICreditVault.sol";

contract CreditVaultProtocol is ICVP, TransientStorage, Types {
    using Set for SetStorage;

    // Constants

    string public constant name = "Credit Vault Protocol - CVP";

    address internal constant ERC1820_REGISTRY = 0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24;

    uint8 internal constant BATCH_DEPTH__INIT = 1;
    uint8 internal constant BATCH_DEPTH__MAX = 10;


    // Storage
    mapping(address account => mapping(address operator => bool isOperator)) public accountOperators;

    ExecutionContext internal executionContext;
    mapping(address account => SetStorage) internal accountCollaterals;
    mapping(address account => SetStorage) internal accountControllers;


    // Events, Errors

    event AccountOperatorSet(address indexed account, address indexed operator, bool isAuthorized);
    
    error NotAuthorized();
    error InvalidAddress();
    error ChecksReentrancy();
    error DeferralViolation();
    error BatchDepthViolation();
    error ControllerViolation(address account);
    error AccountStatusViolation(address account, bytes data);
    error VaultStatusViolation(address vault, bytes data);
    error RevertedBatchResult(BatchResult[] batchItemsResult, BatchResult[] accountsStatusResult, BatchResult[] vaultsStatusResult);
    error BatchPanic();


    // Constructor

    constructor() {
        executionContext.batchDepth = BATCH_DEPTH__INIT;
    }


    // Modifiers

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

    /// @notice A modifier sets onBehalfOfAccount in the execution context to the specified account.
    /// @dev Should be used as the last modifier in the function so that context is limited only to the function body.
    modifier onBehalfOfAccountContext(address account) {
        // must be cached in case of CVP reentrancy
        address onBehalfOfAccountCache = executionContext.onBehalfOfAccount;

        executionContext.onBehalfOfAccount = account;
        _;
        executionContext.onBehalfOfAccount = onBehalfOfAccountCache;
    }

    /// @notice A modifier that prevents the function from being called when checks are deferred (which happens when the execution context is in a batch).
    modifier notInDeferral() {
        if (executionContext.batchDepth != BATCH_DEPTH__INIT) revert DeferralViolation();
        _;
    }


    // Account operators

    /// @notice Sets or unsets an operator for an account.
    /// @dev Only the owner of the account can call this function. An operator is an address that can perform actions for an account on behalf of the owner. 
    /// @param account The address of the account whose operator is being set or unset.
    /// @param operator The address of the operator that is being authorized or deauthorized.
    /// @param isAuthorized A boolean flag that indicates whether the operator is authorized or not.
    function setAccountOperator(address account, address operator, bool isAuthorized) public payable virtual {
        // only the primary account can call this function for any of its sub accounts.
        // the operator can't be the sub account of the account
        if ((uint160(msg.sender) | 0xFF) != (uint160(account) | 0xFF)) revert NotAuthorized();
        else if ((uint160(msg.sender) | 0xFF) == (uint160(operator) | 0xFF)) revert InvalidAddress();

        accountOperators[account][operator] = isAuthorized;
        emit AccountOperatorSet(account, operator, isAuthorized);
    }


    // Execution context

    /// @notice Returns the current execution context.
    /// @dev The execution context consists of checks deferral state and the account on behalf of which the execution flow is being executed at the moment. Checks are deferred if the execution flow is currently in a batch.
    /// @return checksDeferred A boolean flag that indicates whether the checks are deferred or not.
    /// @return onBehalfOfAccount The address of the account on behalf of which the execution flow is being executed at the moment.
    function getExecutionContext() external view returns (bool checksDeferred, address onBehalfOfAccount) {
        ExecutionContext memory context = executionContext;
        checksDeferred = context.batchDepth != BATCH_DEPTH__INIT;
        onBehalfOfAccount = context.onBehalfOfAccount;
    }

    /// @notice Returns the current execution context extended with information whether a controller is enabled for an account.
    /// @dev The execution context consists of checks deferral state and the account on behalf of which the execution flow is being executed at the moment. Checks are deferred if the execution flow is currently in a batch. If msg.sender is not a vault itself, this function cannot be called when the execution context is in a batch, as the controllers may change during the execution flow.
    /// @param account The address of the account for which controller is being checked.
    /// @param vault The address of the controller that is being checked.
    /// @return checksDeferred A boolean flag that indicates whether the checks are deferred or not.
    /// @return onBehalfOfAccount The address of the account on behalf of which the execution flow is being executed at the moment.
    /// @return controllerEnabled A boolean value that indicates whether the vault is controller for the account or not.
    function getExecutionContextExtended(address account, address vault) external view 
    returns (bool checksDeferred, address onBehalfOfAccount, bool controllerEnabled) {
        ExecutionContext memory context = executionContext;
        checksDeferred = context.batchDepth != BATCH_DEPTH__INIT;

        if (msg.sender != vault && checksDeferred) revert DeferralViolation();

        onBehalfOfAccount = context.onBehalfOfAccount;
        controllerEnabled = accountControllers[account].contains(vault);
    }


    // Collaterals management

    /// @notice Returns an array of collaterals for an account.
    /// @dev A collateral is a vault for which account's balances are under the control of the currently chosen controller vault. This function cannot be called when the execution context is in a batch, as the collaterals may change during the execution flow.
    /// @param account The address of the account whose collaterals are being queried.
    /// @return An array of addresses that are the collaterals for the account.
    function getCollaterals(address account) external view notInDeferral returns (address[] memory) {
        return accountCollaterals[account].get();
    }

    /// @notice Returns whether a collateral is enabled for an account.
    /// @dev A collateral is a vault for which account's balances are under the control of the currently chosen controller vault. This function cannot be called when the execution context is in a batch, as the collaterals may change during the execution flow.
    /// @param account The address of the account that is being checked.
    /// @param vault The address of the collateral that is being checked.
    /// @return A boolean value that indicates whether the vault is collateral for the account or not.
    function isCollateralEnabled(address account, address vault) external view notInDeferral returns (bool) {
        return accountCollaterals[account].contains(vault);
    }

    /// @notice Enables a collateral for an account.
    /// @dev A collaterals is a vault for which account's balances are under the control of the currently chosen controller vault. Only the owner or an operator of the account can call this function. Account status checks are performed.
    /// @param account The address for which the collateral is being enabled.
    /// @param vault The address of the collateral being enabled.
    function enableCollateral(address account, address vault) public payable virtual
    ownerOrOperator(account) {
        accountCollaterals[account].insert(vault);
        requireAccountStatusCheck(account);
    }

    /// @notice Disables a collateral for an account.
    /// @dev A collateral is a vault for which account’s balances are under the control of the currently chosen controller vault. Only the owner or an operator of the account can call this function. Account status checks are performed.
    /// @param account The address for which the collateral is being disabled.
    /// @param vault The address of the collateral being disabled. 
    function disableCollateral(address account, address vault) public payable virtual
    ownerOrOperator(account) {
        accountCollaterals[account].remove(vault);
        requireAccountStatusCheck(account);
    }


    // Controllers management

    /// @notice Returns an array of controllers for an account.
    /// @dev A controller is a vault that has been chosen for an account to have special control over account's balances in the collaterals vaults. A user can have multiple controllers within a batch execution, but only one (or none) can be selected when the account status check is performed upon the batch exit. This function cannot be called when the execution context is in a batch, as the controllers may change during the execution flow.
    /// @param account The address of the account whose controllers are being queried.
    /// @return An array of addresses that are the controllers for the account.
    function getControllers(address account) external view notInDeferral returns (address[] memory) {
        return accountControllers[account].get();
    }

    /// @notice Returns whether a controller is enabled for an account.
    /// @dev A controller is a vault that has been chosen for an account to have special control over account’s balances in the collaterals vaults. If msg.sender is not a vault itself, this function cannot be called when the execution context is in a batch, as the controllers may change during the execution flow.
    /// @param account The address of the account that is being checked.
    /// @param vault The address of the controller that is being checked.
    /// @return A boolean value that indicates whether the vault is controller for the account or not.
    function isControllerEnabled(address account, address vault) external view returns (bool) {
        if (msg.sender != vault && executionContext.batchDepth != BATCH_DEPTH__INIT) revert DeferralViolation();
        return accountControllers[account].contains(vault);
    }

    /// @notice Enables a controller for an account.
    /// @dev A controller is a vault that has been chosen for an account to have special control over account’s balances in the collaterals vaults. Only the owner or an operator of the account can call this function. Account status checks are performed.
    /// @param account The address for which the controller is being enabled.
    /// @param vault The address of the controller being enabled. 
    function enableController(address account, address vault) public payable virtual
    ownerOrOperator(account) {        
        accountControllers[account].insert(vault);
        requireAccountStatusCheck(account);
    }

    /// @notice Disables a controller for an account.
    /// @dev A controller is a vault that has been chosen for an account to have special control over account’s balances in the collaterals vaults. Only the vault itself can call this function which means that msg.sender is treated as a calling vault. Account status checks are performed.
    /// @param account The address for which the calling controller is being disabled.
    function disableController(address account) public payable virtual {
        accountControllers[account].remove(msg.sender);
        requireAccountStatusCheck(account);
    }


    // Call forwarding

    /// @notice Calls to a target contract as per data encoded.
    /// @dev This function can be used to interact with any contract. If zero address passed as onBehalfOfAccount, msg.sender is used instead.
    /// @param targetContract The address of the contract to be called.
    /// @param onBehalfOfAccount The address of the account for which it is checked whether msg.sender is authorized to act on its behalf.
    /// @param data The encoded data which is called on the target contract.
    /// @return success A boolean value that indicates whether the call succeeded or not.
    /// @return result Returned data from the call.
    function call(address targetContract, address onBehalfOfAccount, bytes calldata data) public payable
    returns (bool success, bytes memory result) {
        if (targetContract == address(this)) revert InvalidAddress();

        onBehalfOfAccount = onBehalfOfAccount == address(0) ? msg.sender : onBehalfOfAccount;
        (success, result) = callInternal(targetContract, onBehalfOfAccount, msg.value, data);
    }

    /// @notice Calls to one of the enabled collateral vaults from currently enabled controller vault.
    /// @dev This function can be used to interact with any vault if it is enabled as a collateral of the onBehalfOfAccount and the caller is the only controller for the onBehalfOfAccount. If zero address passed as onBehalfOfAccount, msg.sender is used instead.
    /// @param targetContract The address of the contract to be called.
    /// @param onBehalfOfAccount The address of the account for which it is checked whether msg.sender is authorized to act on its behalf.
    /// @param data The encoded data which is called on the target contract.
    /// @return success A boolean value that indicates whether the call succeeded or not.
    /// @return result Returned data from the call. 
    function callFromControllerToCollateral(address targetContract, address onBehalfOfAccount, bytes calldata data) public payable
    returns (bool success, bytes memory result) {
        onBehalfOfAccount = onBehalfOfAccount == address(0) ? msg.sender : onBehalfOfAccount;
        (success, result) = callFromControllerToCollateralInternal(targetContract, onBehalfOfAccount, msg.value, data);
    }


    // Batching

    /// @notice Defers the account and vault checks until the end of the execution flow and executes a batch of batch items.
    /// @dev Accounts status checks and vault status checks are performed after all the batch items have been executed. It's possible to have nested batches where checks are executed ony once after the top level batch concludes.
    /// @param items An array of batch items to be executed.
    function batch(BatchItem[] calldata items) public payable virtual {
        ExecutionContext memory context = executionContext;
        if (context.checksInProgressLock) revert ChecksReentrancy();
        else if (context.batchDepth >= BATCH_DEPTH__MAX) revert BatchDepthViolation();

        unchecked { ++executionContext.batchDepth; }
        batchInternal(items, false);
        unchecked { --executionContext.batchDepth; }

        if (executionContext.batchDepth == BATCH_DEPTH__INIT) {
            executionContext.checksInProgressLock = true;
            checkStatusAll(SetType.Account, false);
            checkStatusAll(SetType.Vault, false);
            executionContext.checksInProgressLock = false;
        }
    }

    /// @notice Defers the account and vault checks until the end of the execution flow and executes a batch of batch items.
    /// @dev This function always reverts as it's only used for simulation purposes. Accounts status checks and vault status checks are performed after all the batch items have been executed.
    /// @param items An array of batch items to be executed.
    /// @return batchItemsResult An array of batch item results for each item.
    /// @return accountsStatusResult An array of account status results for each account.
    /// @return vaultsStatusResult An array of vault status results for each vault.
    function batchRevert(BatchItem[] calldata items) public payable virtual
    returns (BatchResult[] memory batchItemsResult, BatchResult[] memory accountsStatusResult, BatchResult[] memory vaultsStatusResult) {
        ExecutionContext memory context = executionContext;
        if (context.checksInProgressLock) revert ChecksReentrancy();
        else if (context.batchDepth >= BATCH_DEPTH__MAX) revert BatchDepthViolation();

        unchecked { ++executionContext.batchDepth; }
        batchItemsResult = batchInternal(items, true);
        unchecked { --executionContext.batchDepth; }

        if (executionContext.batchDepth == BATCH_DEPTH__INIT) {
            executionContext.checksInProgressLock = true;
            accountsStatusResult= checkStatusAll(SetType.Account, true);
            vaultsStatusResult= checkStatusAll(SetType.Vault, true);
            executionContext.checksInProgressLock = false;
        }

        revert RevertedBatchResult(batchItemsResult, accountsStatusResult, vaultsStatusResult);
    }

    function batchSimulation(BatchItem[] calldata items) public payable virtual
    returns (BatchResult[] memory batchItemsResult, BatchResult[] memory accountsStatusResult, BatchResult[] memory vaultsStatusResult) {        
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
            (BatchResult[], BatchResult[], BatchResult[])
        );
    }


    // Account Status Check

    /// @notice Checks the status of an account and returns whether it is valid or not.
    /// @dev Account status check is performed by calling into selected controller vault and passing the array of currently enabled collaterals. If controller is not selected, the account is considered valid.
    /// @param account The address of the account to be checked.
    /// @return isValid A boolean value that indicates whether the account is valid or not.
    function checkAccountStatus(address account) public view returns (bool isValid) {
        (isValid,) = checkAccountStatusInternal(account);
    }

    /// @notice Checks the status of multiple accounts and returns an array of boolean values that indicate whether each account is valid or not. 
    /// @dev Account status check is performed by calling into selected controller vault and passing the array of currently enabled collaterals. If controller is not selected, the account is considered valid.
    /// @param accounts An array of addresses of the accounts to be checked. 
    /// @return isValid An array of boolean values that indicate whether each account is valid or not.
    function checkAccountsStatus(address[] calldata accounts) public view returns (bool[] memory isValid) {
        isValid = new bool[](accounts.length);
        for (uint i = 0; i < accounts.length;) {
            (isValid[i],) = checkAccountStatusInternal(accounts[i]);
            unchecked { ++i; }
        }
    }

    /// @notice Checks the status of an account and reverts if it is not valid.
    /// @dev If in a batch, the account is added to the set of accounts to be checked at the end of the execution flow. Account status check is performed by calling into selected controller vault and passing the array of currently enabled collaterals. If controller is not selected, the account is always considered valid.
    /// @param account The address of the account to be checked.
    function requireAccountStatusCheck(address account) public virtual {
        if (executionContext.batchDepth == BATCH_DEPTH__INIT) requireAccountStatusCheckInternal(account);
        else accountStatusChecks.insert(account);
    }

    /// @notice Checks the status of multiple accounts and reverts if any of them is not valid.
    /// @dev If in a batch, the accounts are added to the set of accounts to be checked at the end of the execution flow. Account status check is performed by calling into selected controller vault and passing the array of currently enabled collaterals. If controller is not selected, the account is considered valid.
    /// @param accounts An array of addresses of the accounts to be checked.
    function requireAccountsStatusCheck(address[] calldata accounts) public virtual {
        bool checksDeferred = executionContext.batchDepth != BATCH_DEPTH__INIT;
        for (uint i = 0; i < accounts.length;) {
            if (checksDeferred) accountStatusChecks.insert(accounts[i]);
            else requireAccountStatusCheckInternal(accounts[i]);
            unchecked { ++i; }
        }
    }

    // Vault Status Check

    /// @notice Checks the status of a vault and reverts if it is not valid.
    /// @dev If in a batch, the vault is added to the set of vaults to be checked at the end of the execution flow. This function can only be called by the vault itself.
    function requireVaultStatusCheck() public virtual {
        if (executionContext.batchDepth == BATCH_DEPTH__INIT) requireVaultStatusCheckInternal(msg.sender);
        else vaultStatusChecks.insert(msg.sender);
    }


    // INTERNAL FUNCTIONS

    function callInternal(address targetContract, address onBehalfOfAccount, uint msgValue, bytes calldata data) internal virtual
    ownerOrOperator(onBehalfOfAccount)
    onBehalfOfAccountContext(onBehalfOfAccount)
    returns (bool success, bytes memory result) {
        if (targetContract == ERC1820_REGISTRY) revert InvalidAddress();

        msgValue = msgValue == type(uint).max ? address(this).balance : msgValue;
        (success, result) = targetContract.call{value: msgValue}(data);
    }

    function callFromControllerToCollateralInternal(address targetContract, address onBehalfOfAccount, uint msgValue, bytes calldata data) internal virtual
    onBehalfOfAccountContext(onBehalfOfAccount)
    returns (bool success, bytes memory result) {
        SetStorage storage controllers = accountControllers[onBehalfOfAccount];

        if (controllers.numElements != 1) revert ControllerViolation(onBehalfOfAccount);
        else if (
            controllers.firstElement != msg.sender || 
            !accountCollaterals[onBehalfOfAccount].contains(targetContract)
        ) revert NotAuthorized();

        msgValue = msgValue == type(uint).max ? address(this).balance : msgValue;
        (success, result) = targetContract.call{value: msgValue}(data);
    }

    function batchInternal(BatchItem[] calldata items, bool returnResult) internal
    returns (BatchResult[] memory batchItemsResult) {
        if (returnResult) batchItemsResult = new BatchResult[](items.length);

        for (uint i = 0; i < items.length;) {
            BatchItem calldata item = items[i];
            address targetContract = item.targetContract;
            bool success;
            bytes memory result;

            if (targetContract == address(this)) {
                (success, result) = targetContract.delegatecall(item.data);
            } else {
                address onBehalfOfAccount = item.onBehalfOfAccount == address(0) ? msg.sender : item.onBehalfOfAccount;
                (success, result) = callInternal(targetContract, onBehalfOfAccount, item.msgValue, item.data);
            }

            if (returnResult) {
                batchItemsResult[i].success = success;
                batchItemsResult[i].result = result;
            } else if (!(success || item.allowError)) revertBytes(result);

            unchecked { ++i; }
        }
    }

    function checkAccountStatusInternal(address account) internal view 
    returns (bool isValid, bytes memory data) {
        SetStorage storage controllers = accountControllers[account];
        
        if (controllers.numElements == 0) return (true, "");
        else if (controllers.numElements > 1) revert ControllerViolation(account);
        
        address[] memory collaterals = accountCollaterals[account].get();

        (bool success, bytes memory result) = controllers.firstElement.staticcall(
            abi.encodeWithSelector(
                ICreditVault.checkAccountStatus.selector,
                account,
                collaterals
            )
        );

        if (success) (isValid, data) = abi.decode(result, (bool, bytes));
        else isValid = false;
    }

    function requireAccountStatusCheckInternal(address account) internal virtual {
        (bool isValid, bytes memory data) = checkAccountStatusInternal(account);

        if (!isValid) revert AccountStatusViolation(account, data);
    }

    function checkVaultStatusInternal(address vault) internal 
    returns (bool isValid, bytes memory data) {
        (bool success, bytes memory result) = vault.call(
            abi.encodeWithSelector(
                ICreditVault.checkVaultStatus.selector
            )
        );
        
        if (success) (isValid, data) = abi.decode(result, (bool, bytes));
        else isValid = false;
    }

    function requireVaultStatusCheckInternal(address vault) internal virtual {
        (bool isValid, bytes memory data) = checkVaultStatusInternal(vault);

        if (!isValid) revert VaultStatusViolation(vault, data);
    }

    function checkStatusAll(SetType setType, bool returnResult) private 
    returns (BatchResult[] memory result) {
        function (address) returns (bool, bytes memory) checkStatus;
        function (address) requireStatusCheck;
        SetStorage storage setStorage;

        if (setType == SetType.Account) {
            checkStatus = checkAccountStatusInternal;
            requireStatusCheck = requireAccountStatusCheckInternal;
            setStorage = accountStatusChecks;
        } else {
            checkStatus = checkVaultStatusInternal;
            requireStatusCheck = requireVaultStatusCheckInternal;
            setStorage = vaultStatusChecks;
        }

        address firstElement = setStorage.firstElement;
        uint8 numElements = setStorage.numElements;

        if (returnResult) result = new BatchResult[](numElements);
        
        if (numElements == 0) return result;

        for (uint i = 0; i < numElements;) {
            address addr = i == 0 ? firstElement : setStorage.elements[i];
            
            if (returnResult) {
                bytes memory data;
                (result[i].success, data) = checkStatus(addr);

                if (!result[i].success) {
                    bytes4 violationSelector = setType == SetType.Account 
                        ? AccountStatusViolation.selector 
                        : VaultStatusViolation.selector;

                    result[i].result = abi.encodeWithSelector(
                        violationSelector,
                        addr,
                        data
                    );
                }
            } else requireStatusCheck(addr);
            
            delete setStorage.elements[i];
            unchecked { ++i; }
        }

        if (setType == SetType.Account) delete accountStatusChecks;
        else delete vaultStatusChecks;
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


    // Formal verification

    function invariantsCheck() public view {
        ExecutionContext memory context = executionContext;
        assert(context.batchDepth == BATCH_DEPTH__INIT);
        assert(!context.checksInProgressLock);
        assert(context.onBehalfOfAccount == address(0));

        SetStorage storage asChecks = accountStatusChecks;
        assert(asChecks.numElements == 0);
        assert(asChecks.firstElement == address(0));

        SetStorage storage vsChecks = vaultStatusChecks;
        assert(vsChecks.numElements == 0);
        assert(vsChecks.firstElement == address(0));
    }
}
