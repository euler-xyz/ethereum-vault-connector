// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

/// @title ICVC
/// @author Euler Labs (https://www.eulerlabs.com/)
/// @notice This interface defines the methods for the Credit Vault Connector.
interface ICVC {
    /// @notice A struct representing a batch item.
    /// @dev Each batch item represents a single operation to be performed within a checks deferred context.
    struct BatchItem {
        /// @notice The target contract to be called.
        address targetContract;
        /// @notice The account on behalf of which the operation is to be performed. msg.sender must be authorized to act on behalf.
        address onBehalfOfAccount;
        /// @notice The amount of ETH to be forwarded with the call. If the value is type(uint).max, the whole balance of the CVC contract will be forwarded.
        uint value;
        /// @notice The encoded data which is called on the target contract.
        bytes data;
    }

    /// @notice A struct representing the result of a batch item operation.
    /// @dev Used only for simulation purposes.
    struct BatchItemResult {
        /// @notice A boolean indicating whether the operation was successful.
        bool success;
        /// @notice The result of the operation.
        bytes result;
    }

    /// @notice Returns current raw execution context.
    /// @dev When checks in progress, on behalf of account is always address(0).
    /// @return context Current raw execution context.
    function getRawExecutionContext() external view returns (uint context);

    /// @notice Returns the current call depth.
    /// @return The current call depth.
    function getCurrentCallDepth() external view returns (uint);

    /// @notice Returns an account on behalf of which the operation is being executed at the moment and whether the controllerToCheck is an enabled controller for that account.
    /// @dev When checks in progress, on behalf of account is always address(0).
    /// @param controllerToCheck The address of the controller for which it is checked whether it is an enabled controller for the account on behalf of which the operation is being executed at the moment.
    /// @return onBehalfOfAccount An account that has been authenticated and on behalf of which the operation is being executed at the moment.
    /// @return controllerEnabled A boolean value that indicates whether controllerToCheck is an enabled controller for the account on behalf of which the operation is being executed at the moment. Always false if controllerToCheck is address(0).
    function getCurrentOnBehalfOfAccount(
        address controllerToCheck
    ) external view returns (address onBehalfOfAccount, bool controllerEnabled);

    /// @notice Checks if checks are in progress.
    /// @return A boolean indicating whether checks are in progress.
    function areChecksInProgress() external view returns (bool);

    /// @notice Checks if there is an impersonation in progress.
    /// @return A boolean indicating whether an impersonation is in progress.
    function isImpersonationInProgress() external view returns (bool);

    /// @notice Checks if an operator is authenticated.
    /// @return A boolean indicating whether an operator is authenticated.
    function isOperatorAuthenticated() external view returns (bool);

    /// @notice Checks if a simulation is in progress.
    /// @return A boolean indicating whether a simulation is in progress.
    function isSimulationInProgress() external view returns (bool);

    /// @notice Checks whether the specified account and the other account have the same owner.
    /// @dev The function is used to check whether one account is authorized to perform operations on behalf of the other. Accounts are considered to have a common owner if they share the first 19 bytes of their address.
    /// @param account The address of the account that is being checked.
    /// @param otherAccount The address of the other account that is being checked.
    /// @return A boolean flag that indicates whether the accounts have the same owner.
    function haveCommonOwner(
        address account,
        address otherAccount
    ) external pure returns (bool);

    /// @notice Returns the address prefix of the specified account.
    /// @dev The address prefix is the first 19 bytes of the account address.
    /// @param account The address of the account whose address prefix is being retrieved.
    /// @return A uint152 value that represents the address prefix of the account.
    function getAddressPrefix(address account) external pure returns (uint152);

    /// @notice Returns the owner for the specified account.
    /// @dev The function will revert if the owner is not registered. Registration of the owner happens on the initial interaction with the CVC that requires authentication of an owner.
    /// @param account The address of the account whose owner is being retrieved.
    /// @return owner The address of the account owner. An account owner is an EOA/smart contract which address matches the first 19 bytes of the account address.
    function getAccountOwner(address account) external view returns (address);

    /// @notice Returns the nonce for a given address prefix and nonce namespace.
    /// @dev Each nonce namespace provides 256 bit nonce that has to be used seqentially. There's no requirement to use all the nonces for a given nonce namespace before moving to the next one which enables possibility to use permit messages in a non-sequential manner.
    /// @param addressPrefix The address prefix for which the nonce is being retrieved.
    /// @param nonceNamespace The nonce namespace for which the nonce is being retrieved.
    /// @return nonce The current nonce for the given address prefix and nonce namespace.
    function getNonce(
        uint152 addressPrefix,
        uint nonceNamespace
    ) external view returns (uint nonce);

    /// @notice Returns the bit field for a given address prefix and operator.
    /// @dev The bit field is used to store information about authorized operators for a given address prefix. Each bit in the bit field corresponds to one account belonging to the same owner. If the bit is set, the operator is authorized for the account.
    /// @param addressPrefix The address prefix for which the bit field is being retrieved.
    /// @param operator The address of the operator for which the bit field is being retrieved.
    /// @return accountOperatorAuthorized The bit field for the given address prefix and operator.
    function getOperator(
        uint152 addressPrefix,
        address operator
    ) external view returns (uint accountOperatorAuthorized);

    /// @notice Returns information whether given operator has been authorized for the account.
    /// @param account The address of the account whose operator is being checked.
    /// @param operator The address of the operator that is being checked.
    /// @return authorized A boolean value that indicates whether the operator is authorized for the account.
    function isAccountOperatorAuthorized(
        address account,
        address operator
    ) external view returns (bool authorized);

    /// @notice Sets the nonce for a given address prefix and nonce namespace.
    /// @dev This function can only be called by the owner of the address prefix. Each nonce namespace provides 256 bit nonce that has to be used seqentially. There's no requirement to use all the nonces for a given nonce namespace before moving to the next one which enables possibility to use permit messages in a non-sequential manner. To invalidate signed permit messages, set the nonce for a given nonce namespace accordingly. To invalidate all the permit messages for a given nonce namespace, set the nonce to type(uint).max.
    /// @param addressPrefix The address prefix for which the nonce is being set.
    /// @param nonceNamespace The nonce namespace for which the nonce is being set.
    /// @param nonce The new nonce for the given address prefix and nonce namespace.
    function setNonce(
        uint152 addressPrefix,
        uint nonceNamespace,
        uint nonce
    ) external payable;

    /// @notice Sets the bit field for a given address prefix and operator.
    /// @dev This function can only be called by the owner of the address prefix. Each bit in the bit field corresponds to one account belonging to the same owner. If the bit is set, the operator is authorized for the account.
    /// @param addressPrefix The address prefix for which the bit field is being set.
    /// @param operator The address of the operator for which the bit field is being set.
    /// @param accountOperatorAuthorized The new bit field for the given address prefix and operator.
    function setOperator(
        uint152 addressPrefix,
        address operator,
        uint accountOperatorAuthorized
    ) external payable;

    /// @notice Authorizes or deauthorizes an operator for the account.
    /// @dev Only the owner or authorized operator of the account can call this function. An operator is an address that can perform actions for an account on behalf of the owner. If it's an operator calling this function, it can only deauthorize ifself.
    /// @param account The address of the account whose operator is being set or unset.
    /// @param operator The address of the operator that is being installed or uninstalled.
    /// @param authorized A boolean value that indicates whether the operator is being authorized or deauthorized.
    function setAccountOperator(
        address account,
        address operator,
        bool authorized
    ) external payable;

    /// @notice Returns an array of collaterals enabled for an account.
    /// @dev A collateral is a vault for which account's balances are under the control of the currently chosen controller vault.
    /// @param account The address of the account whose collaterals are being queried.
    /// @return An array of addresses that are enabled collaterals for the account.
    function getCollaterals(
        address account
    ) external view returns (address[] memory);

    /// @notice Returns whether a collateral is enabled for an account.
    /// @dev A collateral is a vault for which account's balances are under the control of the currently chosen controller vault.
    /// @param account The address of the account that is being checked.
    /// @param vault The address of the collateral that is being checked.
    /// @return A boolean value that indicates whether the vault is an enabled collateral for the account or not.
    function isCollateralEnabled(
        address account,
        address vault
    ) external view returns (bool);

    /// @notice Enables a collateral for an account.
    /// @dev A collaterals is a vault for which account's balances are under the control of the currently chosen controller vault. Only the owner or an operator of the account can call this function. Account status checks are performed.
    /// @param account The account address for which the collateral is being enabled.
    /// @param vault The address being enabled as a collateral.
    function enableCollateral(address account, address vault) external payable;

    /// @notice Disables a collateral for an account.
    /// @dev A collateral is a vault for which account’s balances are under the control of the currently chosen controller vault. Only the owner or an operator of the account can call this function. Account status checks are performed.
    /// @param account The account address for which the collateral is being disabled.
    /// @param vault The address of a collateral being disabled.
    function disableCollateral(address account, address vault) external payable;

    /// @notice Returns an array of enabled controllers for an account.
    /// @dev A controller is a vault that has been chosen for an account to have special control over account's balances in the enabled collaterals vaults. A user can have multiple controllers during a call execution, but at most one can be selected when the account status check is performed.
    /// @param account The address of the account whose controllers are being queried.
    /// @return An array of addresses that are the enabled controllers for the account.
    function getControllers(
        address account
    ) external view returns (address[] memory);

    /// @notice Returns whether a controller is enabled for an account.
    /// @dev A controller is a vault that has been chosen for an account to have special control over account’s balances in the enabled collaterals vaults.
    /// @param account The address of the account that is being checked.
    /// @param vault The address of the controller that is being checked.
    /// @return A boolean value that indicates whether the vault is enabled controller for the account or not.
    function isControllerEnabled(
        address account,
        address vault
    ) external view returns (bool);

    /// @notice Enables a controller for an account.
    /// @dev A controller is a vault that has been chosen for an account to have special control over account’s balances in the enabled collaterals vaults. Only the owner or an operator of the account can call this function. Account status checks are performed.
    /// @param account The address for which the controller is being enabled.
    /// @param vault The address of the controller being enabled.
    function enableController(address account, address vault) external payable;

    /// @notice Disables a controller for an account.
    /// @dev A controller is a vault that has been chosen for an account to have special control over account’s balances in the enabled collaterals vaults. Only the vault itself can call this function. Account status checks are performed.
    /// @param account The address for which the calling controller is being disabled.
    function disableController(address account) external payable;

    /// @notice Executes signed arbitrary data by self-calling into the CVC.
    /// @dev Low-level call function is used to execute the arbitrary data signed by the owner or the operator on the CVC contract. During that call, CVC becomes msg.sender.
    /// @param signer The address signing the permit message (ECDSA) or verifying the permit message signature (ERC-1271). It's also the owner or the operator of all the accounts for which authentication will be needed during the execution of the arbitrary data call.
    /// @param nonceNamespace The nonce namespace for which the nonce is being used.
    /// @param nonce The nonce for the given account and nonce namespace.
    /// @param deadline The timestamp after which the permit is considered expired.
    /// @param value The amount of ETH to be forwarded with the call. If the value is type(uint).max, the whole balance of the CVC contract will be forwarded.
    /// @param data The encoded data which is self-called on the CVC contract.
    /// @param signature The signature of the data signed by the signer.
    function permit(
        address signer,
        uint nonceNamespace,
        uint nonce,
        uint deadline,
        uint value,
        bytes calldata data,
        bytes calldata signature
    ) external payable;

    /// @notice Calls back into the msg.sender with the context set as per data encoded.
    /// @dev This function defers the account and vault status checks (it's a checks-deferrable call) and increases the call depth for the duration of the call. If the initiall call depth is 0, the account and vault status checks are performed after the call.
    /// @dev This function can be used to defer account and vault status checks by providing calldata and the context with which the msg.sender will be called back.
    /// @param onBehalfOfAccount The address of the account which will be set in the context. It assumes the msg.sender has authenticated the account themselves.
    /// @param value The amount of ETH to be forwarded with the call. If the value is type(uint).max, the whole balance of the CVC contract will be forwarded.
    /// @param data The encoded data which is called on the msg.sender
    /// @return result The result of the call.
    function callback(
        address onBehalfOfAccount,
        uint value,
        bytes calldata data
    ) external payable returns (bytes memory result);

    /// @notice Calls into a target contract as per data encoded.
    /// @dev This function defers the account and vault status checks (it's a checks-deferrable call) and increases the call depth for the duration of the call. If the initiall call depth is 0, the account and vault status checks are performed after the call.
    /// @dev This function can be used to interact with any contract while checks deferred. Only the owner or an operator of the account can call this function.
    /// @param targetContract The address of the contract to be called.
    /// @param onBehalfOfAccount The address of the account for which it is checked whether msg.sender is authorized to act on behalf.
    /// @param value The amount of ETH to be forwarded with the call. If the value is type(uint).max, the whole balance of the CVC contract will be forwarded.
    /// @param data The encoded data which is called on the target contract.
    /// @return result The result of the call.
    function call(
        address targetContract,
        address onBehalfOfAccount,
        uint value,
        bytes calldata data
    ) external payable returns (bytes memory result);

    /// @notice For a given account, calls into one of the enabled collateral vaults from the currently enabled controller vault as per data encoded.
    /// @dev This function defers the account and vault status checks (it's a checks-deferrable call) and increases the call depth for the duration of the call. If the initiall call depth is 0, the account and vault status checks are performed after the call.
    /// @dev This function can be used to interact with any contract while checks deferred as long as the contract is enabled as a collateral of the account and the msg.sender is the only enabled controller of the account.
    /// @param targetCollateral The collateral address to be called.
    /// @param onBehalfOfAccount The address of the account for which it is checked whether msg.sender is authorized to act on behalf.
    /// @param value The amount of ETH to be forwarded with the call. If the value is type(uint).max, the whole balance of the CVC contract will be forwarded.
    /// @param data The encoded data which is called on the target contract.
    /// @return result The result of the call.
    function impersonate(
        address targetCollateral,
        address onBehalfOfAccount,
        uint value,
        bytes calldata data
    ) external payable returns (bytes memory result);

    /// @notice Executes multiple calls into the target contracts while checks deferred as per batch items provided.
    /// @dev This function defers the account and vault status checks (it's a checks-deferrable call) and increases the call depth for the duration of the calls. If the initiall call depth is 0, the account and vault status checks are performed after the calls.
    /// @param items An array of batch items to be executed.
    function batch(BatchItem[] calldata items) external payable;

    /// @notice Executes multiple calls into the target contracts while checks deferred as per batch items provided.
    /// @dev This function always reverts as it's only used for simulation purposes. This function cannot be called within a checks-deferrable call.
    /// @param items An array of batch items to be executed.
    function batchRevert(BatchItem[] calldata items) external payable;

    /// @notice Executes multiple calls into the target contracts while checks deferred as per batch items provided.
    /// @dev This function does not modify state and should only be used for simulation purposes. This function cannot be called within a checks-deferrable call.
    /// @param items An array of batch items to be executed.
    /// @return batchItemsResult An array of batch item results for each item.
    /// @return accountsStatusResult An array of account status results for each account.
    /// @return vaultsStatusResult An array of vault status results for each vault.
    function batchSimulation(
        BatchItem[] calldata items
    )
        external
        payable
        returns (
            BatchItemResult[] memory batchItemsResult,
            BatchItemResult[] memory accountsStatusResult,
            BatchItemResult[] memory vaultsStatusResult
        );

    /// @notice Checks whether the status check is deferred for a given account.
    /// @param account The address of the account for which it is checked whether the status check is deferred.
    /// @return A boolean flag that indicates whether the status check is deferred or not.
    function isAccountStatusCheckDeferred(
        address account
    ) external view returns (bool);

    /// @notice Checks the status of an account and reverts if it is not valid.
    /// @dev If checks deferred, the account is added to the set of accounts to be checked at the end of the top-level checks-deferrable call. Account status check is performed by calling into the selected controller vault and passing the array of currently enabled collaterals. If controller is not selected, the account is always considered valid.
    /// @param account The address of the account to be checked.
    function requireAccountStatusCheck(address account) external payable;

    /// @notice Immediately checks the status of an account and reverts if it is not valid.
    /// @dev Account status check is performed on the fly regardless of the current execution context state. If account status check was previously deferred, it is removed from the set. If controller is not selected, the account is always considered valid.
    /// @param account The address of the account to be checked.
    function requireAccountStatusCheckNow(address account) external payable;

    /// @notice Immediately checks the status of all the accounts for which the checks were deferred and reverts if any of them is not valid.
    /// @dev Account status checks are performed on the fly regardless of the current execution context state. The deferred accounts set is cleared. If controller is not selected for a given, the account is always considered valid.
    function requireAllAccountsStatusCheckNow() external payable;

    /// @notice Forgives previously deferred account status check.
    /// @dev Account address is removed from the set of addresses for which status checks are deferred. This function can only be called by the currently enabled controller of a given account.
    /// @param account The address of the account for which the status check is forgiven.
    function forgiveAccountStatusCheck(address account) external payable;

    /// @notice Checks whether the status check is deferred for a given vault.
    /// @param vault The address of the vault for which it is checked whether the status check is deferred.
    /// @return A boolean flag that indicates whether the status check is deferred or not.
    function isVaultStatusCheckDeferred(
        address vault
    ) external view returns (bool);

    /// @notice Checks the status of a vault and reverts if it is not valid.
    /// @dev If checks deferred, the vault is added to the set of vaults to be checked at the end of the top-level checks-deferrable call. This function can only be called by the vault itself.
    function requireVaultStatusCheck() external payable;

    /// @notice Immediately checks the status of a vault. It reverts if status is not valid.
    /// @dev Vault status check is performed on the fly regardless of the current execution context state. If vault status check was previously deferred, it is removed from the set. This function can only be called by the vault itself. If checking the vault status is a two-step process, i.e. the vault requires its prior state snapshot, this function should be called after the snapshot is taken and the vault should handle the situation when the snapshot is not available then calling this function.
    function requireVaultStatusCheckNow() external payable;

    /// @notice Immediately checks the status of all vaults for which the checks were deferred and reverts if any of them is not valid.
    /// @dev Vault status checks are performed on the fly regardless of the current execution context state. The deferred vaults set is cleared.
    function requireAllVaultsStatusCheckNow() external payable;

    /// @notice Forgives previously deferred vault status check.
    /// @dev Vault address is removed from the set of addresses for which status checks are deferred. This function can only be called by the vault itself.
    function forgiveVaultStatusCheck() external payable;

    /// @notice Checks the status of an account and a vault and reverts if it is not valid.
    /// @dev If checks deferred, the account and the vault are added to the respective sets of accounts and vaults to be checked at the end of the top-level checks-deferrable call. Account status check is performed by calling into selected controller vault and passing the array of currently enabled collaterals. If controller is not selected, the account is always considered valid. This function can only be called by the vault itself.
    /// @param account The address of the account to be checked.
    function requireAccountAndVaultStatusCheck(
        address account
    ) external payable;
}
