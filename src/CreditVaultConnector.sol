// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./Set.sol";
import "./TransientStorage.sol";
import "./interfaces/ICreditVaultConnector.sol";
import "./interfaces/ICreditVault.sol";

/// #define canActOnBehalf(address msgSender, address account) bool = (uint160(msgSender) | 0xFF) == (uint160(account) | 0xFF) || accountOperators[account][msgSender];

/// #if_succeeds "each account has at most 1 controller" forall(uint i in ownerLookup) forall(uint j in 0...256) accountControllers[address(uint160((i << 8) ^ j))].numElements <= 1;
contract CreditVaultConnector is ICVC, TransientStorage {
    using Set for SetStorage;

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                       CONSTANTS                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    string public constant name = "Credit Vault Connector (CVC)";

    address internal constant ERC1820_REGISTRY =
        0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24;

    uint8 internal constant BATCH_DEPTH__INIT = 0;
    uint8 internal constant BATCH_DEPTH__MAX = 9;

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                        STORAGE                                            //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    mapping(address account => mapping(address operator => bool isOperator))
        public accountOperators;

    mapping(address account => SetStorage) internal accountCollaterals;
    mapping(address account => SetStorage) internal accountControllers;

    // Every Ethereum address has 256 accounts in the CVC (including the primary account - called the owner).
    // Each account has an account ID from 0-255, where 0 is the owner account's ID. In order to compute the account
    // addresses, the account ID is treated as a uint and XORed (exclusive ORed) with the Ethereum address.
    // In order to record the owner of a group of 256 accounts, the CVC uses a definition of a prefix. A prefix is a part
    // of an address having the first 19 bytes common with any of the 256 account addresses belonging to the same group.
    // account/152 -> prefix/152
    // To get prefix for the account, it's enough to take the account address and right shift it by 8 bits.
    mapping(uint152 prefix => address owner) internal ownerLookup;

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                        EVENTS                                             //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    event AccountOperatorEnabled(
        address indexed account,
        address indexed operator
    );
    event AccountOperatorDisabled(
        address indexed account,
        address indexed operator
    );
    event AccountsOwnerRegistered(
        uint152 indexed prefix,
        address indexed owner
    );
    event ControllerEnabled(
        address indexed account,
        address indexed controller
    );
    event ControllerDisabled(
        address indexed account,
        address indexed controller
    );

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                         ERRORS                                            //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    error CVC_NotAuthorized();
    error CVC_AccountOwnerNotRegistered();
    error CVC_InvalidAddress();
    error CVC_ChecksReentrancy();
    error CVC_ImpersonateReentancy();
    error CVC_BatchDepthViolation();
    error CVC_ControllerViolation();
    error CVC_AccountStatusViolation(address account, bytes data);
    error CVC_VaultStatusViolation(address vault, bytes data);
    error CVC_RevertedBatchResult(
        BatchItemResult[] batchItemsResult,
        BatchItemResult[] accountsStatusResult,
        BatchItemResult[] vaultsStatusResult
    );
    error CVC_BatchPanic();

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                       MODIFIERS                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice A modifier that allows only the owner or an operator of the account to call the function.
    /// @dev The owner of an account is an address that matches first 19 bytes of the account address. An operator of an account is an address that has been authorized by the owner of an account to perform operations on behalf of the owner.
    /// @param account The address of the account for which it is checked whether msg.sender is the owner or an operator.
    modifier ownerOrOperator(address account) {
        if (
            !haveCommonOwner(msg.sender, account) &&
            !accountOperators[account][msg.sender]
        ) revert CVC_NotAuthorized();
        {
            // if it's an operator calling and we get up to this point
            // (thanks to accountOperators[account][msg.sender] == true), it means that the function setAccountOperator()
            // must have been called previously and the ownerLookup is already set.
            // if it's not an operator calling, it means that owner is msg.sender and the ownerLookup will be set if needed.
            // ownerLookup is set only once on the initial interaction of the account with the CVC.
            uint152 prefix = uint152(uint160(account) >> 8);
            if (ownerLookup[prefix] == address(0)) {
                ownerLookup[prefix] = msg.sender;
                emit AccountsOwnerRegistered(prefix, msg.sender);
            }
        }

        _;
    }

    /// @notice A modifier that checks for checks in progress and impersonate reentrancy.
    modifier nonReentrant() {
        {
            bool checksLock = executionContext.checksLock;
            bool impersonateLock = executionContext.impersonateLock;

            if (checksLock) revert CVC_ChecksReentrancy();
            else if (impersonateLock) revert CVC_ImpersonateReentancy();
        }
        _;
    }

    /// @notice A modifier that sets onBehalfOfAccount in the execution context to the specified account.
    /// @dev Should be used as the last modifier in the function so that context is limited only to the function body.
    modifier onBehalfOfAccountContext(address account) {
        // must be cached in case of CVC reentrancy
        address onBehalfOfAccountCache = executionContext.onBehalfOfAccount;

        executionContext.onBehalfOfAccount = account;
        _;
        executionContext.onBehalfOfAccount = onBehalfOfAccountCache;
    }

    /// @notice A modifier checks whether msg.sender is the only controller for the account.
    modifier authenticateController(address account) {
        {
            uint numOfControllers = accountControllers[account].numElements;
            address controller = accountControllers[account].firstElement;

            if (numOfControllers != 1) revert CVC_ControllerViolation();
            else if (controller != msg.sender) revert CVC_NotAuthorized();
        }
        _;
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                   PUBLIC FUNCTIONS                                        //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    // Account owner and operators

    /** @dev See {ICVC-haveCommonOwner}. */
    function haveCommonOwner(
        address account,
        address otherAccount
    ) public pure returns (bool) {
        return (uint160(account) | 0xFF) == (uint160(otherAccount) | 0xFF);
    }

    /** @dev See {ICVC-getAccountOwner}. */
    function getAccountOwner(
        address account
    ) external view returns (address owner) {
        owner = ownerLookup[uint152(uint160(account) >> 8)];

        if (owner == address(0)) revert CVC_AccountOwnerNotRegistered();
    }

    /** @dev See {ICVC-setAccountOperator}. */
    /// #if_succeeds "only the account owner can call this" haveCommonOwner(msg.sender, account);
    /// #if_succeeds "operator is not a sub-account of the owner" !haveCommonOwner(msg.sender, operator);
    function setAccountOperator(
        address account,
        address operator,
        bool isAuthorized
    ) public payable virtual {
        // only the account owner can call this function for any of its 256 accounts.
        // the operator cannot be one of the 256 accounts that belong to the owner
        if (!haveCommonOwner(msg.sender, account)) {
            revert CVC_NotAuthorized();
        } else if (haveCommonOwner(msg.sender, operator)) {
            revert CVC_InvalidAddress();
        }

        uint152 prefix = uint152(uint160(account) >> 8);
        if (ownerLookup[prefix] == address(0)) {
            ownerLookup[prefix] = msg.sender;
            emit AccountsOwnerRegistered(prefix, msg.sender);
        }

        if (accountOperators[account][operator] == isAuthorized) return;

        accountOperators[account][operator] = isAuthorized;

        if (isAuthorized) emit AccountOperatorEnabled(account, operator);
        else emit AccountOperatorDisabled(account, operator);
    }

    // Execution internals

    /** @dev See {ICVC-getExecutionContext}. */
    function getExecutionContext(
        address controllerToCheck
    )
        external
        view
        returns (ExecutionContext memory context, bool controllerEnabled)
    {
        context = executionContext;
        controllerEnabled = controllerToCheck == address(0)
            ? false
            : accountControllers[context.onBehalfOfAccount].contains(
                controllerToCheck
            );
    }

    /** @dev See {ICVC-isAccountStatusCheckDeferred}. */
    function isAccountStatusCheckDeferred(
        address account
    ) external view returns (bool) {
        return accountStatusChecks.contains(account);
    }

    /** @dev See {ICVC-isVaultStatusCheckDeferred}. */
    function isVaultStatusCheckDeferred(
        address vault
    ) external view returns (bool) {
        return vaultStatusChecks.contains(vault);
    }

    // Collaterals management

    /** @dev See {ICVC-getCollaterals}. */
    function getCollaterals(
        address account
    ) external view returns (address[] memory) {
        return accountCollaterals[account].get();
    }

    /** @dev See {ICVC-isCollateralEnabled}. */
    function isCollateralEnabled(
        address account,
        address vault
    ) external view returns (bool) {
        return accountCollaterals[account].contains(vault);
    }

    /** @dev See {ICVC-enableCollateral}. */
    /// #if_succeds "only the account owner or operator can call this" canActOnBehalf(msg.sender, account);
    /// #if_succeds "is non-reentant" !executionContext.checksLock && !executionContext.impersonateLock;
    /// #if_succeeds "the vault is present in the collateral set 1" old(accountCollaterals[account].numElements) < 20 ==> accountCollaterals[account].contains(vault);
    /// #if_succeeds "number of vault is equal to the collateral array length 1" accountCollaterals[account].numElements == accountCollaterals[account].get().length;
    function enableCollateral(
        address account,
        address vault
    ) public payable virtual ownerOrOperator(account) nonReentrant {
        accountCollaterals[account].insert(vault);
        requireAccountStatusCheck(account);
    }

    /** @dev See {ICVC-disableCollateral}. */
    /// #if_succeds "only the account owner or operator can call this" canActOnBehalf(msg.sender, account);
    /// #if_succeds "is non-reentant" !executionContext.checksLock && !executionContext.impersonateLock;
    /// #if_succeeds "the vault is not present the collateral set 2" !accountCollaterals[account].contains(vault);
    /// #if_succeeds "number of vaults is equal to the collateral array length 2" accountCollaterals[account].numElements == accountCollaterals[account].get().length;
    function disableCollateral(
        address account,
        address vault
    ) public payable virtual ownerOrOperator(account) nonReentrant {
        accountCollaterals[account].remove(vault);
        requireAccountStatusCheck(account);
    }

    // Controllers management

    /** @dev See {ICVC-getControllers}. */
    function getControllers(
        address account
    ) external view returns (address[] memory) {
        return accountControllers[account].get();
    }

    /** @dev See {ICVC-isControllerEnabled}. */
    function isControllerEnabled(
        address account,
        address vault
    ) external view returns (bool) {
        return accountControllers[account].contains(vault);
    }

    /** @dev See {ICVC-enableController}. */
    /// #if_succeds "only the account owner or operator can call this" canActOnBehalf(msg.sender, account);
    /// #if_succeds "is non-reentant" !executionContext.checksLock && !executionContext.impersonateLock;
    /// #if_succeeds "the vault is present in the controller set 1" old(accountControllers[account].numElements) < 20 ==> accountControllers[account].contains(vault);
    /// #if_succeeds "number of vault is equal to the controller array length 1" accountControllers[account].numElements == accountControllers[account].get().length;
    function enableController(
        address account,
        address vault
    ) public payable virtual ownerOrOperator(account) nonReentrant {
        if (accountControllers[account].insert(vault)) {
            emit ControllerEnabled(account, vault);
        }
        requireAccountStatusCheck(account);
    }

    /** @dev See {ICVC-disableController}. */
    /// #if_succeds "is non-reentant" !executionContext.checksLock && !executionContext.impersonateLock;
    /// #if_succeeds "the vault is not present the collateral set 2" !accountControllers[account].contains(msg.sender);
    /// #if_succeeds "number of vaults is equal to the collateral array length 2" accountControllers[account].numElements == accountControllers[account].get().length;
    function disableController(
        address account
    ) public payable virtual nonReentrant {
        if (accountControllers[account].remove(msg.sender)) {
            emit ControllerDisabled(account, msg.sender);
        }
        requireAccountStatusCheck(account);
    }

    // Call forwarding

    /** @dev See {ICVC-call}. */
    /// #if_succeds "only the account owner or operator can call this" canActOnBehalf(msg.sender, onBehalfOfAccount);
    /// #if_succeds "is non-reentant" !executionContext.checksLock && !executionContext.impersonateLock;
    /// #if_succeds "the target can neither be this contract nor ERC-1810 registry" targetContract != address(this) && targetContract != ERC1820_REGISTRY;
    function call(
        address targetContract,
        address onBehalfOfAccount,
        bytes calldata data
    )
        public
        payable
        virtual
        nonReentrant
        returns (bool success, bytes memory result)
    {
        if (targetContract == address(this)) revert CVC_InvalidAddress();

        uint value = executionContext.batchDepth == BATCH_DEPTH__INIT
            ? msg.value
            : 0;

        onBehalfOfAccount = onBehalfOfAccount == address(0)
            ? msg.sender
            : onBehalfOfAccount;

        (success, result) = callInternal(
            targetContract,
            onBehalfOfAccount,
            value,
            data
        );
    }

    /** @dev See {ICVC-impersonate}. */
    /// #if_succeds "is non-reentant" !executionContext.checksLock && !executionContext.impersonateLock;
    /// #if_succeds "only enabled controller can call into enabled collateral" getControllers(onBehalfOfAccount).length == 1 && isControllerEnabled(onBehalfOfAccount, msg.sender) && isCollateralEnabled(onBehalfOfAccount, targetContract);
    /// #if_succeds "the target cannot be this contract" targetContract != address(this);
    function impersonate(
        address targetContract,
        address onBehalfOfAccount,
        bytes calldata data
    )
        public
        payable
        virtual
        nonReentrant
        returns (bool success, bytes memory result)
    {
        if (targetContract == address(this)) revert CVC_InvalidAddress();

        uint value = executionContext.batchDepth == BATCH_DEPTH__INIT
            ? msg.value
            : 0;

        onBehalfOfAccount = onBehalfOfAccount == address(0)
            ? msg.sender
            : onBehalfOfAccount;

        executionContext.impersonateLock = true;

        (success, result) = impersonateInternal(
            targetContract,
            onBehalfOfAccount,
            value,
            data
        );

        executionContext.impersonateLock = false;
    }

    // Batching

    /** @dev See {ICVC-batch}. */
    /// #if_succeds "is non-reentant" !executionContext.checksLock && !executionContext.impersonateLock;
    /// #if_succeds "batch depth doesn't change pre- and post- execution" old(executionContext.batchDepth) == executionContext.batchDepth;
    /// #if_succeds "checks are properly executed 1" executionContext.batchDepth == BATCH_DEPTH__INIT && old(accountStatusChecks.numElements) > 0 ==> accountStatusChecks.numElements == 0;
    /// #if_succeds "checks are properly executed 2" executionContext.batchDepth == BATCH_DEPTH__INIT && old(vaultStatusChecks.numElements) > 0 ==> vaultStatusChecks.numElements == 0;
    function batch(
        BatchItem[] calldata items
    ) public payable virtual nonReentrant {
        uint batchDepthCache = executionContext.batchDepth;

        if (batchDepthCache >= BATCH_DEPTH__MAX) {
            revert CVC_BatchDepthViolation();
        }

        unchecked {
            ++executionContext.batchDepth;
        }

        batchInternal(items, false);

        unchecked {
            --executionContext.batchDepth;
        }

        if (batchDepthCache == BATCH_DEPTH__INIT) {
            executionContext.checksLock = true;
            checkStatusAll(SetType.Account, false);
            checkStatusAll(SetType.Vault, false);
            executionContext.checksLock = false;
        }
    }

    /** @dev See {ICVC-batchRevert}. */
    /// #if_succeds "this function must always revert" false;
    function batchRevert(
        BatchItem[] calldata items
    )
        public
        payable
        virtual
        nonReentrant
        returns (
            BatchItemResult[] memory batchItemsResult,
            BatchItemResult[] memory accountsStatusResult,
            BatchItemResult[] memory vaultsStatusResult
        )
    {
        uint batchDepthCache = executionContext.batchDepth;

        if (batchDepthCache >= BATCH_DEPTH__MAX) {
            revert CVC_BatchDepthViolation();
        }

        unchecked {
            ++executionContext.batchDepth;
        }

        batchItemsResult = batchInternal(items, true);

        unchecked {
            --executionContext.batchDepth;
        }

        if (batchDepthCache == BATCH_DEPTH__INIT) {
            executionContext.checksLock = true;
            accountsStatusResult = checkStatusAll(SetType.Account, true);
            vaultsStatusResult = checkStatusAll(SetType.Vault, true);
            executionContext.checksLock = false;
        }

        revert CVC_RevertedBatchResult(
            batchItemsResult,
            accountsStatusResult,
            vaultsStatusResult
        );
    }

    /** @dev See {ICVC-batchSimulation}. */
    function batchSimulation(
        BatchItem[] calldata items
    )
        public
        payable
        virtual
        returns (
            BatchItemResult[] memory batchItemsResult,
            BatchItemResult[] memory accountsStatusResult,
            BatchItemResult[] memory vaultsStatusResult
        )
    {
        (bool success, bytes memory result) = address(this).delegatecall(
            abi.encodeWithSelector(this.batchRevert.selector, items)
        );

        if (success) {
            revert CVC_BatchPanic();
        } else if (bytes4(result) != CVC_RevertedBatchResult.selector) {
            revertBytes(result);
        }

        assembly {
            result := add(result, 4)
        }

        (batchItemsResult, accountsStatusResult, vaultsStatusResult) = abi
            .decode(
                result,
                (BatchItemResult[], BatchItemResult[], BatchItemResult[])
            );
    }

    // Account Status Check

    /** @dev See {ICVC-checkAccountStatus}. */
    function checkAccountStatus(
        address account
    ) public view returns (bool isValid) {
        (isValid, ) = checkAccountStatusInternal(account);
    }

    /** @dev See {ICVC-checkAccountsStatus}. */
    function checkAccountsStatus(
        address[] calldata accounts
    ) public view returns (bool[] memory isValid) {
        isValid = new bool[](accounts.length);

        uint length = accounts.length;
        for (uint i; i < length; ) {
            (isValid[i], ) = checkAccountStatusInternal(accounts[i]);
            unchecked {
                ++i;
            }
        }
    }

    /** @dev See {ICVC-requireAccountStatusCheck}. */
    /// #if_succeds "account is added to the set only if checks deferred" executionContext.batchDepth != BATCH_DEPTH__INIT ==> accountStatusChecks.contains(account);
    function requireAccountStatusCheck(address account) public virtual {
        if (executionContext.batchDepth == BATCH_DEPTH__INIT) {
            requireAccountStatusCheckInternal(account);
        } else {
            accountStatusChecks.insert(account);
        }
    }

    /** @dev See {ICVC-requireAccountsStatusCheck}. */
    /// #if_succeds "accounts are added to the set only if checks deferred" executionContext.batchDepth != BATCH_DEPTH__INIT ==> forall(address i in accounts) accountStatusChecks.contains(i);
    function requireAccountsStatusCheck(
        address[] calldata accounts
    ) public virtual {
        uint batchDepthCache = executionContext.batchDepth;

        uint length = accounts.length;
        for (uint i; i < length; ) {
            if (batchDepthCache == BATCH_DEPTH__INIT) {
                requireAccountStatusCheckInternal(accounts[i]);
            } else {
                accountStatusChecks.insert(accounts[i]);
            }

            unchecked {
                ++i;
            }
        }
    }

    /** @dev See {ICVC-requireAccountStatusCheckNow}. */
    /// #if_succeds "account is never added to the set or it's removed if previously present" !accountStatusChecks.contains(account);
    function requireAccountStatusCheckNow(address account) public virtual {
        requireAccountStatusCheckInternal(account);
        accountStatusChecks.remove(account);
    }

    /** @dev See {ICVC-requireAccountsStatusCheckNow}. */
    /// #if_succeds "accounts are never added to the set or they're removed if previously present" forall(address i in accounts) !accountStatusChecks.contains(i);
    function requireAccountsStatusCheckNow(
        address[] calldata accounts
    ) public virtual {
        uint length = accounts.length;
        for (uint i; i < length; ) {
            address account = accounts[i];
            requireAccountStatusCheckInternal(account);
            accountStatusChecks.remove(account);

            unchecked {
                ++i;
            }
        }
    }

    /** @dev See {ICVC-forgiveAccountStatusCheck}. */
    /// #if_succeds "account is never present in the set after calling this" !accountStatusChecks.contains(account);
    function forgiveAccountStatusCheck(
        address account
    ) public virtual authenticateController(account) {
        accountStatusChecks.remove(account);
    }

    /** @dev See {ICVC-forgiveAccountsStatusCheck}. */
    /// #if_succeds "accounts are never present in the set after calling this" forall(address i in accounts) !accountStatusChecks.contains(i);
    function forgiveAccountsStatusCheck(
        address[] calldata accounts
    ) public virtual {
        uint length = accounts.length;
        for (uint i; i < length; ) {
            address account = accounts[i];
            uint numOfControllers = accountControllers[account].numElements;
            address controller = accountControllers[account].firstElement;

            if (numOfControllers != 1) revert CVC_ControllerViolation();
            else if (controller != msg.sender) revert CVC_NotAuthorized();

            accountStatusChecks.remove(account);

            unchecked {
                ++i;
            }
        }
    }

    // Vault Status Check

    /** @dev See {ICVC-requireVaultStatusCheck}. */
    /// #if_succeds "vault is added to the set only if checks deferred" executionContext.batchDepth != BATCH_DEPTH__INIT ==> vaultStatusChecks.contains(msg.sender);
    function requireVaultStatusCheck() public virtual {
        if (executionContext.batchDepth == BATCH_DEPTH__INIT) {
            requireVaultStatusCheckInternal(msg.sender);
        } else {
            vaultStatusChecks.insert(msg.sender);
        }
    }

    /** @dev See {ICVC-forgiveVaultStatusCheck}. */
    /// #if_succeds "vault is never present in the set after calling this" !vaultStatusChecks.contains(msg.sender);
    function forgiveVaultStatusCheck() external {
        vaultStatusChecks.remove(msg.sender);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                  INTERNAL FUNCTIONS                                       //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    function callInternal(
        address targetContract,
        address onBehalfOfAccount,
        uint value,
        bytes calldata data
    )
        internal
        virtual
        ownerOrOperator(onBehalfOfAccount)
        onBehalfOfAccountContext(onBehalfOfAccount)
        returns (bool success, bytes memory result)
    {
        if (targetContract == ERC1820_REGISTRY) revert CVC_InvalidAddress();

        value = value == type(uint).max ? address(this).balance : value;

        (success, result) = targetContract.call{value: value}(data);
    }

    /// #if_succeeds "impersonate reentrancy guard must be locked" executionContext.impersonateLock;
    function impersonateInternal(
        address targetContract,
        address onBehalfOfAccount,
        uint value,
        bytes calldata data
    )
        internal
        authenticateController(onBehalfOfAccount)
        onBehalfOfAccountContext(onBehalfOfAccount)
        returns (bool success, bytes memory result)
    {
        if (!accountCollaterals[onBehalfOfAccount].contains(targetContract)) {
            revert CVC_NotAuthorized();
        }

        (success, result) = targetContract.call{value: value}(data);
    }

    /// #if_succeeds "batch depth is in range" executionContext.batchDepth > BATCH_DEPTH__INIT && executionContext.batchDepth <= BATCH_DEPTH__MAX;
    function batchInternal(
        BatchItem[] calldata items,
        bool returnResult
    ) internal returns (BatchItemResult[] memory batchItemsResult) {
        if (returnResult) {
            batchItemsResult = new BatchItemResult[](items.length);
        }

        uint length = items.length;
        for (uint i; i < length; ) {
            BatchItem calldata item = items[i];
            address targetContract = item.targetContract;
            bool success;
            bytes memory result;

            if (targetContract == address(this)) {
                (success, result) = address(this).delegatecall(item.data);
            } else {
                address onBehalfOfAccount = item.onBehalfOfAccount == address(0)
                    ? msg.sender
                    : item.onBehalfOfAccount;

                (success, result) = callInternal(
                    targetContract,
                    onBehalfOfAccount,
                    item.value,
                    item.data
                );
            }

            if (returnResult) {
                batchItemsResult[i].success = success;
                batchItemsResult[i].result = result;
            } else if (!(success || item.allowError)) {
                revertBytes(result);
            }

            unchecked {
                ++i;
            }
        }
    }

    /// #if_succeeds "must have at most one controller" accountControllers[account].numElements <= 1;
    function checkAccountStatusInternal(
        address account
    ) internal view returns (bool isValid, bytes memory data) {
        uint numOfControllers = accountControllers[account].numElements;
        address controller = accountControllers[account].firstElement;

        if (numOfControllers == 0) return (true, "");
        else if (numOfControllers > 1) revert CVC_ControllerViolation();

        bool success;
        (success, data) = controller.staticcall(
            abi.encodeWithSelector(
                ICreditVault.checkAccountStatus.selector,
                account,
                accountCollaterals[account].get()
            )
        );

        if (success) (isValid, data) = abi.decode(data, (bool, bytes));
    }

    function requireAccountStatusCheckInternal(
        address account
    ) internal virtual {
        (bool isValid, bytes memory data) = checkAccountStatusInternal(account);

        if (!isValid) revert CVC_AccountStatusViolation(account, data);
    }

    function checkVaultStatusInternal(
        address vault
    ) internal returns (bool isValid, bytes memory data) {
        bool success;
        (success, data) = vault.call(
            abi.encodeWithSelector(ICreditVault.checkVaultStatus.selector)
        );

        if (success) (isValid, data) = abi.decode(data, (bool, bytes));
    }

    function requireVaultStatusCheckInternal(address vault) internal virtual {
        (bool isValid, bytes memory data) = checkVaultStatusInternal(vault);

        if (!isValid) revert CVC_VaultStatusViolation(vault, data);
    }

    /// #if_succeeds "checks reentrancy guard must be locked" executionContext.checksLock;
    /// #if_succeeds "appropriate set must be empty after execution 1" setType == SetType.Account ==> accountStatusChecks.numElements == 0;
    /// #if_succeeds "appropriate set must be empty after execution 2" setType == SetType.Vault ==> vaultStatusChecks.numElements == 0;
    /// #if_succeeds "execution context stays untouched" old(keccak256(abi.encode(executionContext))) == keccak256(abi.encode(executionContext));
    function checkStatusAll(
        SetType setType,
        bool returnResult
    ) private returns (BatchItemResult[] memory result) {
        function(address) returns (bool, bytes memory) checkStatus;
        function(address) requireStatusCheck;
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

        uint numElements = setStorage.numElements;
        address firstElement = setStorage.firstElement;

        if (returnResult) result = new BatchItemResult[](numElements);

        if (numElements == 0) return result;

        // clear only the number of elements to optimize gas consumption
        if (setType == SetType.Account) accountStatusChecks.numElements = 0;
        else vaultStatusChecks.numElements = 0;

        for (uint i; i < numElements; ) {
            address addressToCheck = i == 0
                ? firstElement
                : setStorage.elements[i];

            if (returnResult) {
                bytes memory data;
                (result[i].success, data) = checkStatus(addressToCheck);

                if (!result[i].success) {
                    bytes4 violationSelector = setType == SetType.Account
                        ? CVC_AccountStatusViolation.selector
                        : CVC_VaultStatusViolation.selector;

                    result[i].result = abi.encodeWithSelector(
                        violationSelector,
                        addressToCheck,
                        data
                    );
                }
            } else {
                requireStatusCheck(addressToCheck);
            }

            unchecked {
                ++i;
            }
        }
    }

    // Error handling

    function revertBytes(bytes memory errMsg) internal pure {
        if (errMsg.length != 0) {
            assembly {
                revert(add(32, errMsg), mload(errMsg))
            }
        }
        revert("CVC-empty-error");
    }
}
