// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./Set.sol";
import "./TransientStorage.sol";
import "./interfaces/ICreditVaultConnector.sol";
import "./interfaces/ICreditVault.sol";

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
    error CVC_ImpersonateReentrancy();
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
        {
            uint152 prefix = uint152(uint160(account) >> 8);
            address owner = ownerLookup[prefix];
            if (
                !(owner == msg.sender ||
                    (owner == address(0) &&
                        haveCommonOwnerInternal(account, msg.sender)) ||
                    accountOperators[account][msg.sender])
            ) revert CVC_NotAuthorized();

            // if it's an operator calling and we get up to this point
            // (thanks to accountOperators[account][msg.sender] == true), it means that the function setAccountOperator()
            // must have been called previously and the ownerLookup is already set.
            // if it's not an operator calling, it means that owner is msg.sender and the ownerLookup will be set if needed.
            // ownerLookup is set only once on the initial interaction of the account with the CVC.
            if (owner == address(0)) {
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
            if (impersonateLock) revert CVC_ImpersonateReentrancy();
        }
        _;
    }

    /// @notice A modifier that checks for checks in progress reentrancy and sets the lock.
    modifier nonReentrantChecks() {
        if (executionContext.checksLock) revert CVC_ChecksReentrancy();

        executionContext.checksLock = true;
        _;
        executionContext.checksLock = false;
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

    /// @inheritdoc ICVC
    function haveCommonOwner(
        address account,
        address otherAccount
    ) external pure returns (bool) {
        return haveCommonOwnerInternal(account, otherAccount);
    }

    /// @inheritdoc ICVC
    function getAccountOwner(
        address account
    ) external view returns (address owner) {
        owner = ownerLookup[uint152(uint160(account) >> 8)];

        if (owner == address(0)) revert CVC_AccountOwnerNotRegistered();
    }

    /// @inheritdoc ICVC
    function setAccountOperator(
        address account,
        address operator,
        bool isAuthorized
    ) public payable virtual {
        uint152 prefix = uint152(uint160(account) >> 8);
        address owner = ownerLookup[prefix];

        // only the account owner can call this function for any of its 256 accounts.
        // the operator cannot be one of the 256 accounts that belong to the owner
        if (
            !(owner == msg.sender ||
                (owner == address(0) &&
                    haveCommonOwnerInternal(account, msg.sender)))
        ) {
            revert CVC_NotAuthorized();
        } else if (haveCommonOwnerInternal(operator, msg.sender)) {
            revert CVC_InvalidAddress();
        }

        if (owner == address(0)) {
            ownerLookup[prefix] = msg.sender;
            emit AccountsOwnerRegistered(prefix, msg.sender);
        }

        if (accountOperators[account][operator] == isAuthorized) return;

        accountOperators[account][operator] = isAuthorized;

        if (isAuthorized) emit AccountOperatorEnabled(account, operator);
        else emit AccountOperatorDisabled(account, operator);
    }

    // Execution internals

    /// @inheritdoc ICVC
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

    /// @inheritdoc ICVC
    function isAccountStatusCheckDeferred(
        address account
    ) external view returns (bool) {
        return accountStatusChecks.contains(account);
    }

    /// @inheritdoc ICVC
    function isVaultStatusCheckDeferred(
        address vault
    ) external view returns (bool) {
        return vaultStatusChecks.contains(vault);
    }

    // Collaterals management

    /// @inheritdoc ICVC
    function getCollaterals(
        address account
    ) external view returns (address[] memory) {
        return accountCollaterals[account].get();
    }

    /// @inheritdoc ICVC
    function isCollateralEnabled(
        address account,
        address vault
    ) external view returns (bool) {
        return accountCollaterals[account].contains(vault);
    }

    /// @inheritdoc ICVC
    function enableCollateral(
        address account,
        address vault
    ) public payable virtual nonReentrant ownerOrOperator(account) {
        accountCollaterals[account].insert(vault);
        requireAccountStatusCheck(account);
    }

    /// @inheritdoc ICVC
    function disableCollateral(
        address account,
        address vault
    ) public payable virtual nonReentrant ownerOrOperator(account) {
        accountCollaterals[account].remove(vault);
        requireAccountStatusCheck(account);
    }

    // Controllers management

    /// @inheritdoc ICVC
    function getControllers(
        address account
    ) external view returns (address[] memory) {
        return accountControllers[account].get();
    }

    /// @inheritdoc ICVC
    function isControllerEnabled(
        address account,
        address vault
    ) external view returns (bool) {
        return accountControllers[account].contains(vault);
    }

    /// @inheritdoc ICVC
    function enableController(
        address account,
        address vault
    ) public payable virtual nonReentrant ownerOrOperator(account) {
        if (accountControllers[account].insert(vault)) {
            emit ControllerEnabled(account, vault);
        }
        requireAccountStatusCheck(account);
    }

    /// @inheritdoc ICVC
    function disableController(
        address account
    ) public payable virtual nonReentrant {
        if (accountControllers[account].remove(msg.sender)) {
            emit ControllerDisabled(account, msg.sender);
        }
        requireAccountStatusCheck(account);
    }

    // Call forwarding

    /// @inheritdoc ICVC
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

    /// @inheritdoc ICVC
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

        (success, result) = impersonateInternal(
            targetContract,
            onBehalfOfAccount,
            value,
            data
        );
    }

    // Batching

    /// @inheritdoc ICVC
    function batch(
        BatchItem[] calldata items
    ) public payable virtual nonReentrant {
        uint batchDepth = executionContext.batchDepth;

        if (batchDepth >= BATCH_DEPTH__MAX) {
            revert CVC_BatchDepthViolation();
        }

        unchecked {
            ++executionContext.batchDepth;
        }

        batchInternal(items, false);

        unchecked {
            --executionContext.batchDepth;
        }

        if (batchDepth == BATCH_DEPTH__INIT) {
            executionContext.checksLock = true;
            checkStatusAll(SetType.Account, false);
            checkStatusAll(SetType.Vault, false);
            executionContext.checksLock = false;
        }
    }

    /// @inheritdoc ICVC
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
        uint batchDepth = executionContext.batchDepth;

        if (batchDepth >= BATCH_DEPTH__MAX) {
            revert CVC_BatchDepthViolation();
        }

        unchecked {
            ++executionContext.batchDepth;
        }

        batchItemsResult = batchInternal(items, true);

        unchecked {
            --executionContext.batchDepth;
        }

        if (batchDepth == BATCH_DEPTH__INIT) {
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

    /// @inheritdoc ICVC
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

    /// @inheritdoc ICVC
    function checkAccountStatus(
        address account
    ) public payable nonReentrantChecks returns (bool isValid) {
        (isValid, ) = checkAccountStatusInternal(account);
    }

    /// @inheritdoc ICVC
    function checkAccountsStatus(
        address[] calldata accounts
    ) public payable nonReentrantChecks returns (bool[] memory isValid) {
        isValid = new bool[](accounts.length);

        uint length = accounts.length;
        for (uint i; i < length; ) {
            (isValid[i], ) = checkAccountStatusInternal(accounts[i]);
            unchecked {
                ++i;
            }
        }
    }

    /// @inheritdoc ICVC
    function requireAccountStatusCheck(
        address account
    ) public payable virtual nonReentrantChecks {
        if (executionContext.batchDepth == BATCH_DEPTH__INIT) {
            requireAccountStatusCheckInternal(account);
        } else {
            accountStatusChecks.insert(account);
        }
    }

    /// @inheritdoc ICVC
    function requireAccountsStatusCheck(
        address[] calldata accounts
    ) public payable virtual nonReentrantChecks {
        uint batchDepth = executionContext.batchDepth;
        uint length = accounts.length;
        for (uint i; i < length; ) {
            if (batchDepth == BATCH_DEPTH__INIT) {
                requireAccountStatusCheckInternal(accounts[i]);
            } else {
                accountStatusChecks.insert(accounts[i]);
            }

            unchecked {
                ++i;
            }
        }
    }

    /// @inheritdoc ICVC
    function requireAccountStatusCheckNow(
        address account
    ) public payable virtual nonReentrantChecks {
        accountStatusChecks.remove(account);
        requireAccountStatusCheckInternal(account);
    }

    /// @inheritdoc ICVC
    function requireAccountsStatusCheckNow(
        address[] calldata accounts
    ) public payable virtual nonReentrantChecks {
        uint length = accounts.length;
        for (uint i; i < length; ) {
            address account = accounts[i];
            accountStatusChecks.remove(account);
            requireAccountStatusCheckInternal(account);

            unchecked {
                ++i;
            }
        }
    }

    /// @inheritdoc ICVC
    function requireAllAccountsStatusCheckNow()
        public
        payable
        virtual
        nonReentrantChecks
    {
        checkStatusAll(SetType.Account, false);
    }

    /// @inheritdoc ICVC
    function forgiveAccountStatusCheck(
        address account
    )
        public
        payable
        virtual
        nonReentrantChecks
        authenticateController(account)
    {
        accountStatusChecks.remove(account);
    }

    /// @inheritdoc ICVC
    function forgiveAccountsStatusCheck(
        address[] calldata accounts
    ) public payable virtual nonReentrantChecks {
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

    /// @inheritdoc ICVC
    function requireVaultStatusCheck()
        public
        payable
        virtual
        nonReentrantChecks
    {
        if (executionContext.batchDepth == BATCH_DEPTH__INIT) {
            requireVaultStatusCheckInternal(msg.sender);
        } else {
            vaultStatusChecks.insert(msg.sender);
        }
    }

    /// @inheritdoc ICVC
    function requireVaultStatusCheckNow(
        address vault
    ) public payable virtual nonReentrantChecks {
        if (vaultStatusChecks.remove(vault)) {
            requireVaultStatusCheckInternal(vault);
        }
    }

    /// @inheritdoc ICVC
    function requireVaultsStatusCheckNow(
        address[] calldata vaults
    ) public payable virtual nonReentrantChecks {
        uint length = vaults.length;
        for (uint i; i < length; ) {
            address vault = vaults[i];
            if (vaultStatusChecks.remove(vault)) {
                requireVaultStatusCheckInternal(vault);
            }

            unchecked {
                ++i;
            }
        }
    }

    /// @inheritdoc ICVC
    function requireAllVaultsStatusCheckNow()
        public
        payable
        virtual
        nonReentrantChecks
    {
        checkStatusAll(SetType.Vault, false);
    }

    /// @inheritdoc ICVC
    function forgiveVaultStatusCheck() external payable nonReentrantChecks {
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

        executionContext.impersonateLock = true;

        (success, result) = targetContract.call{value: value}(data);

        executionContext.impersonateLock = false;
    }

    function batchInternal(
        BatchItem[] calldata items,
        bool returnResult
    ) internal returns (BatchItemResult[] memory batchItemsResult) {
        uint length = items.length;

        if (returnResult) {
            batchItemsResult = new BatchItemResult[](length);
        }

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
            } else if (!success) {
                revertBytes(result);
            }

            unchecked {
                ++i;
            }
        }
    }

    function checkAccountStatusInternal(
        address account
    ) internal returns (bool isValid, bytes memory data) {
        uint numOfControllers = accountControllers[account].numElements;
        address controller = accountControllers[account].firstElement;

        if (numOfControllers == 0) return (true, "");
        else if (numOfControllers > 1) revert CVC_ControllerViolation();

        bool success;
        (success, data) = controller.call(
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
        setStorage.numElements = 0;

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

    // Auxiliary functions

    function haveCommonOwnerInternal(
        address account,
        address otherAccount
    ) internal pure returns (bool) {
        return (uint160(account) | 0xFF) == (uint160(otherAccount) | 0xFF);
    }

    function revertBytes(bytes memory errMsg) internal pure {
        if (errMsg.length != 0) {
            assembly {
                revert(add(32, errMsg), mload(errMsg))
            }
        }
        revert("CVC-empty-error");
    }

    // Formal verification

    function invariantsCheck() public view {
        ExecutionContext memory context = executionContext;
        assert(context.batchDepth == BATCH_DEPTH__INIT);
        assert(!context.checksLock);
        assert(!context.impersonateLock);
        assert(context.onBehalfOfAccount == address(0));
        assert(accountStatusChecks.numElements == 0);
        assert(vaultStatusChecks.numElements == 0);
    }
}
