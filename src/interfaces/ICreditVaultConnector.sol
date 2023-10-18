// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

interface ICVC {
    struct BatchItem {
        address targetContract;
        address onBehalfOfAccount;
        uint value;
        bytes data;
    }

    struct BatchItemResult {
        bool success;
        bytes result;
    }

    /// @notice Returns current raw execution context.
    /// @dev Check for checks reentrancy in order to consume on behalf of account.
    /// @return context Current raw execution context.
    function getRawExecutionContext() external view returns (uint context);

    /// @notice Returns an account on behalf of which the operation is being executed at the moment and whether the controllerToCheck is an enabled controller for that account.
    /// @param controllerToCheck The address of the controller for which it is checked whether it is an enabled controller for the account on behalf of which the operation is being executed at the moment.
    /// @return onBehalfOfAccount An account that has been authenticated and on behalf of which the operation is being executed at the moment.
    /// @return controllerEnabled A boolean value that indicates whether controllerToCheck is an enabled controller for the account on behalf of which the operation is being executed at the moment. Always false if controllerToCheck is address(0).
    function getExecutionContext(
        address controllerToCheck
    ) external view returns (address onBehalfOfAccount, bool controllerEnabled);

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

    /// @notice Returns the nonce for a given account and nonce namespace.
    /// @dev Each nonce namespace provides 256 bit nonce that has to be used seqentially. There's no requirement to use all the nonces for a given nonce namespace before moving to the next one which enables possibility to use permit messages in a non-sequential manner.
    /// @param account The address of the account for which the nonce is being retrieved.
    /// @param nonceNamespace The nonce namespace for which the nonce is being retrieved.
    /// @return nonce The current nonce for the given account and nonce namespace.
    function getNonce(
        address account,
        uint nonceNamespace
    ) external view returns (uint nonce);

    /// @notice Returns information whether given operator has been authorized for the account.
    /// @param account The address of the account whose operator is being checked.
    /// @param operator The address of the operator that is being checked.
    /// @return authorized A boolean value that indicates whether the operator is authorized for the account.
    function isAccountOperatorAuthorized(
        address account,
        address operator
    ) external view returns (bool authorized);

    /// @notice Sets the nonce for a given account and nonce namespace.
    /// @dev This function can only be called by the owner of the account. Each nonce namespace provides 256 bit nonce that has to be used seqentially. There's no requirement to use all the nonces for a given nonce namespace before moving to the next one which enables possibility to use permit messages in a non-sequential manner. To invalidate signed permit messages, set the nonce for a given nonce namespace accordingly. To invalidate all the permit messages for a given nonce namespace, set the nonce to type(uint).max.
    /// @param account The address of the account for which the nonce is being set.
    /// @param nonceNamespace The nonce namespace for which the nonce is being set.
    /// @param nonce The new nonce for the given account and nonce namespace.
    function setNonce(
        address account,
        uint nonceNamespace,
        uint nonce
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
    /// @dev A controller is a vault that has been chosen for an account to have special control over account's balances in the enabled collaterals vaults. A user can have multiple controllers during a batch execution, but at most one can be selected when the account status check is performed at the end of the top-level batch.
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

    /// @notice Calls to a target contract as per data encoded.
    /// @dev This function can be used to interact with any contract. It prevents sending ETH if it's called from a batch via delegatecall. If zero address passed as onBehalfOfAccount, msg.sender is used instead.
    /// @param targetContract The address of the contract to be called.
    /// @param onBehalfOfAccount The address of the account for which it is checked whether msg.sender is authorized to act on its behalf.
    /// @param data The encoded data which is called on the target contract.
    function call(
        address targetContract,
        address onBehalfOfAccount,
        bytes calldata data
    ) external payable;

    /// @notice For a given account, calls to one of the enabled collateral vaults from currently enabled controller vault as per data encoded.
    /// @dev This function can be used to interact with any vault if it is enabled as a collateral of the onBehalfOfAccount and the caller is the only enabled controller of the onBehalfOfAccount. This function prevents sending ETH if it's called from a batch via delegatecall. If zero address passed as onBehalfOfAccount, msg.sender is used instead.
    /// @param targetContract The address of the contract to be called.
    /// @param onBehalfOfAccount The address of the account for which it is checked whether msg.sender is authorized to act on its behalf.
    /// @param data The encoded data which is called on the target contract.
    function impersonate(
        address targetContract,
        address onBehalfOfAccount,
        bytes calldata data
    ) external payable;

    /// @notice Executes signed arbitrary data by self-calling into the CVC.
    /// @dev Low-level call function is used to execute the arbitrary data signed by the owner on the CVC contract. During that call, CVC becomes msg.sender.
    /// @param signer The address signing the permit message (ECDSA) or verifying the permit message signature (ERC-1271). It's also an owner of all the accounts for which authentication will be needed during the execution of the arbitrary data call.
    /// @param nonceNamespace The nonce namespace for which the nonce is being used.
    /// @param nonce The nonce for the given account and nonce namespace.
    /// @param deadline The timestamp after which the permit is considered expired.
    /// @param data The encoded data which is self-called on the CVC contract.
    /// @param signature The signature of the data signed by the signer.
    function permit(
        address signer,
        uint nonceNamespace,
        uint nonce,
        uint deadline,
        bytes calldata data,
        bytes calldata signature
    ) external payable;

    /// @notice Defers the account and vault status checks until the end of the top-level batch and executes a batch of batch items.
    /// @dev Accounts status checks and vault status checks are performed after all the batch items of the last batch have been executed. It's possible to have nested batches where checks are executed ony once after the top level batch concludes.
    /// @param items An array of batch items to be executed.
    function batch(BatchItem[] calldata items) external payable;

    /// @notice Defers the account and vault status checks until the end of the top-level batch and executes a batch of batch items.
    /// @dev This function always reverts as it's only used for simulation purposes. Accounts status checks and vault status checks are performed after all the batch items of the last batch have been executed.
    /// @param items An array of batch items to be executed.
    /// @return batchItemsResult An array of batch item results for each item.
    /// @return accountsStatusResult An array of account status results for each account.
    /// @return vaultsStatusResult An array of vault status results for each vault.
    function batchRevert(
        BatchItem[] calldata items
    )
        external
        payable
        returns (
            BatchItemResult[] memory batchItemsResult,
            BatchItemResult[] memory accountsStatusResult,
            BatchItemResult[] memory vaultsStatusResult
        );

    /// @notice Defers the account and vault status checks until the end of the top-level batch and executes a batch of batch items.
    /// @dev This function does not modify state and should only be used for simulation purposes. Accounts status checks and vault status checks are performed after all the batch items of the last batch have been executed.
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
    /// @dev The account status check can only be deferred if a batch of items is being executed.
    /// @param account The address of the account for which it is checked whether the status check is deferred.
    /// @return A boolean flag that indicates whether the status check is deferred or not.
    function isAccountStatusCheckDeferred(
        address account
    ) external view returns (bool);

    /// @notice Checks the status of an account and returns whether it is valid or not.
    /// @dev Account status check is performed by calling into selected controller vault and passing the array of currently enabled collaterals. If controller is not selected, the account is considered valid.
    /// @param account The address of the account to be checked.
    /// @return isValid A boolean value that indicates whether the account is valid or not.
    function checkAccountStatus(
        address account
    ) external payable returns (bool isValid);

    /// @notice Checks the status of multiple accounts and returns an array of boolean values that indicate whether each account is valid or not.
    /// @dev Account status check is performed by calling into selected controller vault and passing the array of currently enabled collaterals. If controller is not selected, the account is considered valid.
    /// @param accounts An array of addresses of the accounts to be checked.
    /// @return isValid An array of boolean values that indicate whether each account is valid or not.
    function checkAccountsStatus(
        address[] calldata accounts
    ) external payable returns (bool[] memory isValid);

    /// @notice Checks the status of an account and reverts if it is not valid.
    /// @dev If in a batch, the account is added to the set of accounts to be checked at the end of the top-level batch (account status check is considered deferred). Account status check is performed by calling into selected controller vault and passing the array of currently enabled collaterals. If controller is not selected, the account is always considered valid.
    /// @param account The address of the account to be checked.
    function requireAccountStatusCheck(address account) external payable;

    /// @notice Checks the status of multiple accounts and reverts if any of them is not valid.
    /// @dev If in a batch, the accounts are added to the set of accounts to be checked at the end of the top-level batch (account status check is considered deferred). Account status check is performed by calling into selected controller vault and passing the array of currently enabled collaterals. If controller is not selected, the account is considered valid.
    /// @param accounts An array of addresses of the accounts to be checked.
    function requireAccountsStatusCheck(
        address[] calldata accounts
    ) external payable;

    /// @notice Immediately checks the status of an account and reverts if it is not valid.
    /// @dev Account status check is performed on the fly regardless of the current execution context state. If account status check was previously deferred, it is removed from the set.
    /// @param account The address of the account to be checked.
    function requireAccountStatusCheckNow(address account) external payable;

    /// @notice Immediately checks the status of multiple accounts and reverts if any of them is not valid.
    /// @dev Account status checks are performed on the fly regardless of the current execution context state. If account status check was previously deferred, it is removed from the set.
    /// @param accounts An array of addresses of the accounts to be checked.
    function requireAccountsStatusCheckNow(
        address[] calldata accounts
    ) external payable;

    /// @notice Immediately checks the status of all accounts for which the checks were deferred and reverts if any of them is not valid.
    /// @dev Account status checks are performed on the fly regardless of the current execution context state. The deferred accounts set is cleared.
    function requireAllAccountsStatusCheckNow() external payable;

    /// @notice Forgives previously deferred account status check.
    /// @dev Account address is removed from the set of addresses for which status checks are deferred. This function can only be called by the currently enabled controller of a given account.
    /// @param account The address of the account for which the status check is forgiven.
    function forgiveAccountStatusCheck(address account) external payable;

    /// @notice Forgives previously deferred account status checks.
    /// @dev Account addresses are removed from the set of addresses for which status checks are deferred. This function can only be called by the currently enabled controller of a given account.
    /// @param accounts An array of addresses of the accounts for which the status checks are forgiven.
    function forgiveAccountsStatusCheck(
        address[] calldata accounts
    ) external payable;

    /// @notice Checks whether the status check is deferred for a given vault.
    /// @dev The vault status check can only be deferred if a batch of items is being executed.
    /// @param vault The address of the vault for which it is checked whether the status check is deferred.
    /// @return A boolean flag that indicates whether the status check is deferred or not.
    function isVaultStatusCheckDeferred(
        address vault
    ) external view returns (bool);

    /// @notice Checks the status of a vault and reverts if it is not valid.
    /// @dev If in a batch, the vault is added to the set of vaults to be checked at the end of the top-level batch (vault status check is considered deferred). This function can only be called by the vault itself.
    function requireVaultStatusCheck() external payable;

    /// @notice Immediately checks the status of a vault if the check had been deferred by it prior to this call. It reverts if status is not valid.
    /// @dev Vault status check is performed on the fly regardless of the current execution context state, but only if the check had been deferred by the vault prior to this call. If vault status check was previously deferred, it is removed from the set.
    /// @param vault The address of the vault to be checked.
    function requireVaultStatusCheckNow(address vault) external payable;

    /// @notice Immediately checks the status of multiple vaults if their checks have been deferred by them prior to this call. It reverts if any of the statuses is not valid.
    /// @dev Vault status checks are performed on the fly regardless of the current execution context state, but only if the check for a vault had been deferred by it prior to this call. If given vault status check was previously deferred, it is removed from the set.
    /// @param vaults An array of addresses of the vaults to be checked.
    function requireVaultsStatusCheckNow(
        address[] calldata vaults
    ) external payable;

    /// @notice Immediately checks the status of all vaults for which the checks were deferred and reverts if any of them is not valid.
    /// @dev Vault status checks are performed on the fly regardless of the current execution context state. The deferred vaults set is cleared.
    function requireAllVaultsStatusCheckNow() external payable;

    /// @notice Forgives previously deferred vault status check.
    /// @dev Vault address is removed from the set of addresses for which status checks are deferred. This function can only be called by the vault itself.
    function forgiveVaultStatusCheck() external payable;

    /// @notice Checks the status of an account and a vault and reverts if it is not valid.
    /// @dev If in a batch, the account and the vault are added to the respective sets of accounts and vaults to be checked at the end of the top-level batch (status checks are considered deferred). Account status check is performed by calling into selected controller vault and passing the array of currently enabled collaterals. If controller is not selected, the account is always considered valid. This function can only be called by the vault itself.
    /// @param account The address of the account to be checked.
    function requireAccountAndVaultStatusCheck(
        address account
    ) external payable;
}
