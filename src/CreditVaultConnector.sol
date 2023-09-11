// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "./Set.sol";
import "./TransientStorage.sol";
import "./interfaces/ICreditVaultConnector.sol";
import "./interfaces/ICreditVault.sol";
import "./interfaces/IERC1271.sol";

contract CreditVaultConnector is TransientStorage, ICVC {
    using Set for SetStorage;

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                       CONSTANTS                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    string public constant name = "Credit Vault Connector (CVC)";
    string public constant version = "1";

    bytes32 public constant OPERATOR_PERMIT_TYPEHASH =
        keccak256(
            "OperatorPermit(address account,address operator,uint40 authExpiryTimestamp,uint40 signatureTimestamp,uint40 signatureDeadlineTimestamp)"
        );

    bytes32 internal constant TYPE_HASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    bytes32 internal constant HASHED_NAME = keccak256(bytes(name));
    bytes32 internal constant HASHED_VERSION = keccak256(bytes(version));

    address internal constant ERC1820_REGISTRY =
        0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24;

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                        STORAGE                                            //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    mapping(address account => SetStorage) internal accountCollaterals;
    mapping(address account => SetStorage) internal accountControllers;

    // Every Ethereum address has 256 accounts in the CVC (including the primary account - called the owner).
    // Each account has an account ID from 0-255, where 0 is the owner account's ID. In order to compute the account
    // addresses, the account ID is treated as a uint and XORed (exclusive ORed) with the Ethereum address.
    // In order to record the owner of a group of 256 accounts, the CVC uses a definition of a prefix. A prefix is a part
    // of an address having the first 19 bytes common with any of the 256 account addresses belonging to the same group.
    // account/152 -> prefix/152
    // To get prefix for the account, it's enough to take the account address and right shift it by 8 bits.

    struct OwnerStorage {
        address owner;
        uint40 lastSignatureTimestamp;
    }

    mapping(uint152 prefix => OwnerStorage) internal ownerLookup;

    struct OperatorStorage {
        uint40 authExpiryTimestamp;
        uint40 lastSignatureTimestamp;
    }

    mapping(address account => mapping(address operator => OperatorStorage))
        internal operatorLookup;

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                        EVENTS                                             //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    event AccountsOwnerRegistered(
        uint152 indexed prefix,
        address indexed owner
    );
    event AccountOperatorAuthorized(
        address indexed account,
        address indexed operator,
        uint authExpiryTimestamp
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
    error CVC_InvalidTimestamp();
    error CVC_InvalidSignature();
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

    /// @notice A modifier that allows only the owner of the account to call the function.
    /// @dev The owner of an account is an address that matches first 19 bytes of the account address and has been recorded (or will be) as an owner in the ownerLookup.
    /// @param account The address of the account for which it is checked whether msg.sender is the owner.
    modifier onlyOwner(address account) {
        if (haveCommonOwnerInternal(account, msg.sender)) {
            address owner = getAccountOwnerInternal(account);

            if (owner == address(0)) {
                setAccountOwnerInternal(account, msg.sender);
            } else if (owner != msg.sender) {
                revert CVC_NotAuthorized();
            }
        } else {
            revert CVC_NotAuthorized();
        }

        _;
    }

    /// @notice A modifier that allows only the owner or an operator of the account to call the function.
    /// @dev The owner of an account is an address that matches first 19 bytes of the account address and has been recorded (or will be) as an owner in the ownerLookup. An operator of an account is an address that has been authorized by the owner of an account to perform operations on behalf of the owner.
    /// @param account The address of the account for which it is checked whether msg.sender is the owner or an operator.
    modifier onlyOwnerOrOperator(address account) {
        if (haveCommonOwnerInternal(account, msg.sender)) {
            address owner = getAccountOwnerInternal(account);

            if (owner == address(0)) {
                setAccountOwnerInternal(account, msg.sender);
            } else if (owner != msg.sender) {
                revert CVC_NotAuthorized();
            }
        } else if (
            operatorLookup[account][msg.sender].authExpiryTimestamp <
            block.timestamp
        ) {
            revert CVC_NotAuthorized();
        }

        _;
    }

    /// @notice A modifier checks whether msg.sender is the only controller for the account.
    modifier onlyController(address account) {
        {
            uint numOfControllers = accountControllers[account].numElements;
            address controller = accountControllers[account].firstElement;

            if (numOfControllers != 1) revert CVC_ControllerViolation();
            if (controller != msg.sender) revert CVC_NotAuthorized();
        }

        _;
    }

    /// @notice A modifier that verifies whether account or vault status checks are reentered as well as checks for impersonate reentrancy.
    modifier nonReentrant() {
        {
            uint context = executionContext;

            if (context & EC__CHECKS_LOCK_MASK != 0) {
                revert CVC_ChecksReentrancy();
            }

            if (context & EC__IMPERSONATE_LOCK_MASK != 0) {
                revert CVC_ImpersonateReentrancy();
            }
        }

        _;
    }

    /// @notice A modifier that verifies whether account or vault status checks are reentered and sets the lock.
    modifier nonReentrantChecks() {
        uint context = executionContext;

        if (context & EC__CHECKS_LOCK_MASK != 0) {
            revert CVC_ChecksReentrancy();
        }

        executionContext = context | EC__CHECKS_LOCK_MASK;

        // TODO leave only _;
        // uint contextCache = executionContext;
        _;
        // assert(contextCache == executionContext);

        executionContext = context & ~EC__CHECKS_LOCK_MASK;
    }

    /// @notice A modifier that sets onBehalfOfAccount in the execution context to the specified account.
    /// @dev Should be used as the last modifier in the function so that context is limited only to the function body.
    modifier onBehalfOfAccountContext(address account) {
        // on behalf account must be cached in case of allowed CVC reentrancy
        uint context = executionContext;
        uint onBehalfOfAccountCache = context & EC__ON_BEHALF_OF_ACCOUNT_MASK;
        uint accountShifted = uint(uint160(account)) <<
            EC__ON_BEHALF_OF_ACCOUNT_OFFSET;

        // update the context only if the account differs
        if (onBehalfOfAccountCache != accountShifted) {
            executionContext =
                (context & ~EC__ON_BEHALF_OF_ACCOUNT_MASK) |
                accountShifted;
        }

        // TODO leave only _;
        // uint contextCache = executionContext;
        _;
        // assert(contextCache == executionContext);

        // restore cached account only if the checks are not deferred or when the account
        // has been updated from non-zero address. thanks to that, we may keep the account in
        // the context for the next batch item.
        // if the checks are deferred, the account will be cleared after all batch items are executed
        if (
            (context & EC__BATCH_DEPTH_MASK == EC__BATCH_DEPTH__INIT) ||
            (onBehalfOfAccountCache != 0 &&
                onBehalfOfAccountCache != accountShifted)
        ) {
            executionContext =
                (context & ~EC__ON_BEHALF_OF_ACCOUNT_MASK) |
                onBehalfOfAccountCache;
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                   PUBLIC FUNCTIONS                                        //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    // Execution internals

    /// @inheritdoc ICVC
    function getRawExecutionContext() external view returns (uint context) {
        context = executionContext;
    }

    /// @inheritdoc ICVC
    function getExecutionContext(
        address controllerToCheck
    )
        public
        view
        virtual
        returns (address onBehalfOfAccount, bool controllerEnabled)
    {
        uint context = executionContext;

        // execution context must be checks reentrancy protected because on behalf of account
        // might be inconsistent while checks are in progress
        if (context & EC__CHECKS_LOCK_MASK != 0) {
            revert CVC_ChecksReentrancy();
        }

        onBehalfOfAccount = address(
            uint160(
                (context & EC__ON_BEHALF_OF_ACCOUNT_MASK) >>
                    EC__ON_BEHALF_OF_ACCOUNT_OFFSET
            )
        );

        controllerEnabled = controllerToCheck == address(0)
            ? false
            : accountControllers[onBehalfOfAccount].contains(controllerToCheck);
    }

    // Owners and operators

    /// @inheritdoc ICVC
    function haveCommonOwner(
        address account,
        address otherAccount
    ) external pure returns (bool) {
        return haveCommonOwnerInternal(account, otherAccount);
    }

    /// @inheritdoc ICVC
    function getPrefix(address account) external pure returns (uint152) {
        return getPrefixInternal(account);
    }

    /// @inheritdoc ICVC
    function getAccountOwner(
        address account
    ) external view returns (address owner) {
        owner = getAccountOwnerInternal(account);

        if (owner == address(0)) revert CVC_AccountOwnerNotRegistered();
    }

    /// @inheritdoc ICVC
    function getAccountOperatorAuthExpiryTimestamp(
        address account,
        address operator
    ) external view returns (uint40 authExpiryTimestamp) {
        return operatorLookup[account][operator].authExpiryTimestamp;
    }

    /// @inheritdoc ICVC
    function invalidateAllPermits()
        public
        payable
        virtual
        onlyOwner(msg.sender)
    {
        uint152 prefix = getPrefixInternal(msg.sender);
        ownerLookup[prefix].lastSignatureTimestamp = uint40(block.timestamp);
    }

    /// @inheritdoc ICVC
    function invalidateAccountOperatorPermits(
        address account,
        address operator
    ) public payable virtual onlyOwner(account) {
        operatorLookup[account][operator].lastSignatureTimestamp = uint40(
            block.timestamp
        );
    }

    /// @inheritdoc ICVC
    function setAccountOperator(
        address account,
        address operator,
        uint40 authExpiryTimestamp
    ) public payable virtual onlyOwner(account) {
        setAccountOperatorInternal(
            msg.sender,
            account,
            operator,
            authExpiryTimestamp,
            false
        );
    }

    /// @inheritdoc ICVC
    function setAccountOperatorPermitECDSA(
        address account,
        address operator,
        uint40 authExpiryTimestamp,
        uint40 signatureTimestamp,
        uint40 signatureDeadlineTimestamp,
        bytes calldata signature
    ) public payable virtual {
        bytes32 permit = getOperatorPermit(
            account,
            operator,
            authExpiryTimestamp,
            signatureTimestamp,
            signatureDeadlineTimestamp
        );
        address owner = getAccountOwnerInternal(account);
        address signer = recoverECDSASigner(permit, signature);

        if (
            !(owner == signer ||
                (owner == address(0) &&
                    haveCommonOwnerInternal(signer, account)))
        ) {
            revert CVC_NotAuthorized();
        }

        if (owner == address(0)) {
            setAccountOwnerInternal(account, signer);
        }

        setAccountOperatorInternal(
            signer,
            account,
            operator,
            authExpiryTimestamp,
            true
        );
    }

    /// @inheritdoc ICVC
    function setAccountOperatorPermitERC1271(
        address account,
        address operator,
        uint40 authExpiryTimestamp,
        uint40 signatureTimestamp,
        uint40 signatureDeadlineTimestamp,
        bytes calldata signature,
        address erc1271Signer
    ) public payable virtual {
        bytes32 permit = getOperatorPermit(
            account,
            operator,
            authExpiryTimestamp,
            signatureTimestamp,
            signatureDeadlineTimestamp
        );
        address owner = getAccountOwnerInternal(account);
        address signer = owner != address(0) ? owner : erc1271Signer;

        if (
            !(haveCommonOwnerInternal(signer, account) &&
                isValidERC1271Signature(signer, permit, signature))
        ) {
            revert CVC_NotAuthorized();
        }

        if (owner == address(0)) {
            setAccountOwnerInternal(account, signer);
        }

        setAccountOperatorInternal(
            signer,
            account,
            operator,
            authExpiryTimestamp,
            true
        );
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
    ) public payable virtual nonReentrant onlyOwnerOrOperator(account) {
        accountCollaterals[account].insert(vault);
        requireAccountStatusCheck(account);
    }

    /// @inheritdoc ICVC
    function disableCollateral(
        address account,
        address vault
    ) public payable virtual nonReentrant onlyOwnerOrOperator(account) {
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
    ) public payable virtual nonReentrant onlyOwnerOrOperator(account) {
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

        uint value = executionContext & EC__BATCH_DEPTH_MASK ==
            EC__BATCH_DEPTH__INIT
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

        uint context = executionContext;

        uint value = context & EC__BATCH_DEPTH_MASK == EC__BATCH_DEPTH__INIT
            ? msg.value
            : 0;

        onBehalfOfAccount = onBehalfOfAccount == address(0)
            ? msg.sender
            : onBehalfOfAccount;

        executionContext = context | EC__IMPERSONATE_LOCK_MASK;

        (success, result) = impersonateInternal(
            targetContract,
            onBehalfOfAccount,
            value,
            data
        );

        executionContext &= ~EC__IMPERSONATE_LOCK_MASK;
    }

    // Batching

    /// @inheritdoc ICVC
    function batch(
        BatchItem[] calldata items
    ) public payable virtual nonReentrant {
        uint context = executionContext;
        uint batchDepth = context & EC__BATCH_DEPTH_MASK;

        if (batchDepth >= EC__BATCH_DEPTH__MAX) {
            revert CVC_BatchDepthViolation();
        }

        unchecked {
            // increases batch depth
            ++context;
        }

        executionContext = context;

        batchInternal(items, false);

        context = executionContext;

        unchecked {
            // decreases batch depth
            --context;
        }

        if (batchDepth == EC__BATCH_DEPTH__INIT) {
            // clear on behalf of account after all batch items are executed
            context &= ~EC__ON_BEHALF_OF_ACCOUNT_MASK;

            executionContext = context | EC__CHECKS_LOCK_MASK;

            // TODO leave only checkStatusAll calls
            uint contextCache = executionContext;
            checkStatusAll(SetType.Account, false);
            checkStatusAll(SetType.Vault, false);
            assert(contextCache == executionContext);
        }

        executionContext = context;
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
        uint context = executionContext;
        uint batchDepth = context & EC__BATCH_DEPTH_MASK;

        if (batchDepth >= EC__BATCH_DEPTH__MAX) {
            revert CVC_BatchDepthViolation();
        }

        unchecked {
            // increases batch depth
            ++context;
        }

        executionContext = context;

        batchItemsResult = batchInternal(items, true);

        context = executionContext;

        unchecked {
            // decreases batch depth
            --context;
        }

        if (batchDepth == EC__BATCH_DEPTH__INIT) {
            // clear on behalf of account after all batch items are executed
            context &= ~EC__ON_BEHALF_OF_ACCOUNT_MASK;

            executionContext = context | EC__CHECKS_LOCK_MASK;

            // TODO leave only checkStatusAll calls
            uint contextCache = executionContext;
            accountsStatusResult = checkStatusAll(SetType.Account, true);
            vaultsStatusResult = checkStatusAll(SetType.Vault, true);
            assert(contextCache == executionContext);
        }

        executionContext = context;

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
            abi.encodeCall(this.batchRevert, items)
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
    function isAccountStatusCheckDeferred(
        address account
    ) external view returns (bool) {
        return accountStatusChecks.contains(account);
    }

    /// @inheritdoc ICVC
    function checkAccountStatus(
        address account
    ) public payable virtual nonReentrantChecks returns (bool isValid) {
        (isValid, ) = checkAccountStatusInternal(account);
    }

    /// @inheritdoc ICVC
    function checkAccountsStatus(
        address[] calldata accounts
    )
        public
        payable
        virtual
        nonReentrantChecks
        returns (bool[] memory isValid)
    {
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
        if (executionContext & EC__BATCH_DEPTH_MASK == EC__BATCH_DEPTH__INIT) {
            requireAccountStatusCheckInternal(account);
        } else {
            accountStatusChecks.insert(account);
        }
    }

    /// @inheritdoc ICVC
    function requireAccountsStatusCheck(
        address[] calldata accounts
    ) public payable virtual nonReentrantChecks {
        uint batchDepth = executionContext & EC__BATCH_DEPTH_MASK;
        uint length = accounts.length;
        for (uint i; i < length; ) {
            if (batchDepth == EC__BATCH_DEPTH__INIT) {
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
    ) public payable virtual nonReentrantChecks onlyController(account) {
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
    function isVaultStatusCheckDeferred(
        address vault
    ) external view returns (bool) {
        return vaultStatusChecks.contains(vault);
    }

    /// @inheritdoc ICVC
    function requireVaultStatusCheck()
        public
        payable
        virtual
        nonReentrantChecks
    {
        if (executionContext & EC__BATCH_DEPTH_MASK == EC__BATCH_DEPTH__INIT) {
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
    function forgiveVaultStatusCheck()
        public
        payable
        virtual
        nonReentrantChecks
    {
        vaultStatusChecks.remove(msg.sender);
    }

    /// @inheritdoc ICVC
    function requireAccountAndVaultStatusCheck(
        address account
    ) public payable virtual nonReentrantChecks {
        if (executionContext & EC__BATCH_DEPTH_MASK == EC__BATCH_DEPTH__INIT) {
            requireAccountStatusCheckInternal(account);
            requireVaultStatusCheckInternal(msg.sender);
        } else {
            accountStatusChecks.insert(account);
            vaultStatusChecks.insert(msg.sender);
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                  INTERNAL FUNCTIONS                                       //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    function setAccountOperatorInternal(
        address owner,
        address account,
        address operator,
        uint40 authExpiryTimestamp,
        bool updateSignatureTimestamp
    ) internal {
        // the operator cannot be one of the 256 accounts that belong to the owner
        if (haveCommonOwnerInternal(owner, operator)) {
            revert CVC_InvalidAddress();
        }

        if (authExpiryTimestamp == type(uint40).max) {
            authExpiryTimestamp = uint40(block.timestamp);
        }

        OperatorStorage memory operatorCache = operatorLookup[account][
            operator
        ];

        if (operatorCache.authExpiryTimestamp != authExpiryTimestamp) {
            operatorLookup[account][operator] = OperatorStorage({
                authExpiryTimestamp: authExpiryTimestamp,
                lastSignatureTimestamp: updateSignatureTimestamp
                    ? uint40(block.timestamp)
                    : operatorCache.lastSignatureTimestamp
            });

            emit AccountOperatorAuthorized(
                account,
                operator,
                authExpiryTimestamp
            );
        } else if (updateSignatureTimestamp) {
            operatorLookup[account][operator].lastSignatureTimestamp = uint40(
                block.timestamp
            );
        }
    }

    function callInternal(
        address targetContract,
        address onBehalfOfAccount,
        uint value,
        bytes calldata data
    )
        internal
        virtual
        onlyOwnerOrOperator(onBehalfOfAccount)
        onBehalfOfAccountContext(onBehalfOfAccount)
        returns (bool success, bytes memory result)
    {
        if (targetContract == ERC1820_REGISTRY) revert CVC_InvalidAddress();

        value = value == type(uint).max ? address(this).balance : value;

        (success, result) = callTargetContractInternal(
            targetContract,
            onBehalfOfAccount,
            value,
            data
        );
    }

    function impersonateInternal(
        address targetContract,
        address onBehalfOfAccount,
        uint value,
        bytes calldata data
    )
        internal
        virtual
        onlyController(onBehalfOfAccount)
        onBehalfOfAccountContext(onBehalfOfAccount)
        returns (bool success, bytes memory result)
    {
        if (!accountCollaterals[onBehalfOfAccount].contains(targetContract)) {
            revert CVC_NotAuthorized();
        }

        (success, result) = callTargetContractInternal(
            targetContract,
            onBehalfOfAccount,
            value,
            data
        );
    }

    function batchInternal(
        BatchItem[] calldata items,
        bool returnResult
    ) internal virtual returns (BatchItemResult[] memory batchItemsResult) {
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
    ) internal virtual returns (bool isValid, bytes memory data) {
        uint numOfControllers = accountControllers[account].numElements;
        address controller = accountControllers[account].firstElement;

        if (numOfControllers == 0) return (true, "");
        else if (numOfControllers > 1) revert CVC_ControllerViolation();

        bool success;
        (success, data) = controller.call(
            abi.encodeCall(
                ICreditVault.checkAccountStatus,
                (account, accountCollaterals[account].get())
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
            abi.encodeCall(ICreditVault.checkVaultStatus, ())
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
    ) internal virtual returns (BatchItemResult[] memory result) {
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

        setStorage.numElements = 0;

        for (uint i; i < numElements; ) {
            address addressToCheck;
            if (i == 0) {
                addressToCheck = firstElement;
                delete setStorage.firstElement;
            } else {
                addressToCheck = setStorage.elements[i].value;
                delete setStorage.elements[i].value;
            }

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

    // Permit-related functions

    function getOperatorPermit(
        address account,
        address operator,
        uint40 authExpiryTimestamp,
        uint40 signatureTimestamp,
        uint40 signatureDeadlineTimestamp
    ) internal view returns (bytes32 permit) {
        uint152 prefix = getPrefixInternal(account);
        uint lastSignatureTimestampOwner = ownerLookup[prefix]
            .lastSignatureTimestamp;
        uint lastSignatureTimestampAccountOperator = operatorLookup[account][
            operator
        ].lastSignatureTimestamp;
        uint lastSignatureTimestamp = lastSignatureTimestampOwner >
            lastSignatureTimestampAccountOperator
            ? lastSignatureTimestampOwner
            : lastSignatureTimestampAccountOperator;

        if (
            signatureTimestamp <= lastSignatureTimestamp ||
            signatureTimestamp > block.timestamp ||
            signatureDeadlineTimestamp < block.timestamp
        ) {
            revert CVC_InvalidTimestamp();
        }

        bytes32 domainSeparator = keccak256(
            abi.encode(
                TYPE_HASH,
                HASHED_NAME,
                HASHED_VERSION,
                block.chainid,
                address(this)
            )
        );

        bytes32 structHash = keccak256(
            abi.encode(
                OPERATOR_PERMIT_TYPEHASH,
                account,
                operator,
                authExpiryTimestamp,
                signatureTimestamp,
                signatureDeadlineTimestamp
            )
        );

        // Assembly block based on:
        // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "\x19\x01")
            mstore(add(ptr, 0x02), domainSeparator)
            mstore(add(ptr, 0x22), structHash)
            permit := keccak256(ptr, 0x42)
        }
    }

    // Based on:
    // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol
    function recoverECDSASigner(
        bytes32 hash,
        bytes memory signature
    ) internal pure returns (address signer) {
        if (signature.length != 65) revert CVC_InvalidSignature();

        bytes32 r;
        bytes32 s;
        uint8 v;

        // ecrecover takes the signature parameters, and the only way to get them
        // currently is to use assembly.
        /// @solidity memory-safe-assembly
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        if (
            uint256(s) >
            0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        ) {
            revert CVC_InvalidSignature();
        }

        // If the signature is valid (and not malleable), return the signer address
        signer = ecrecover(hash, v, r, s);

        if (signer == address(0)) revert CVC_InvalidSignature();
    }

    // Based on:
    // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/SignatureChecker.sol
    function isValidERC1271Signature(
        address signer,
        bytes32 hash,
        bytes memory signature
    ) internal view returns (bool isValid) {
        (bool success, bytes memory result) = signer.staticcall(
            abi.encodeCall(IERC1271.isValidSignature, (hash, signature))
        );

        isValid =
            success &&
            result.length >= 32 &&
            abi.decode(result, (bytes32)) ==
            bytes32(IERC1271.isValidSignature.selector);
    }

    // Auxiliary functions

    function haveCommonOwnerInternal(
        address account,
        address otherAccount
    ) internal pure returns (bool) {
        return (uint160(account) | 0xFF) == (uint160(otherAccount) | 0xFF);
    }

    function getPrefixInternal(
        address account
    ) internal pure returns (uint152) {
        return uint152(uint160(account) >> 8);
    }

    function getAccountOwnerInternal(
        address account
    ) internal view returns (address) {
        uint152 prefix = getPrefixInternal(account);
        return ownerLookup[prefix].owner;
    }

    function setAccountOwnerInternal(address account, address owner) internal {
        uint152 prefix = getPrefixInternal(account);
        ownerLookup[prefix].owner = owner;
        emit AccountsOwnerRegistered(prefix, owner);
    }

    function callTargetContractInternal(
        address targetContract,
        address,
        uint value,
        bytes calldata data
    ) internal virtual returns (bool success, bytes memory result) {
        (success, result) = targetContract.call{value: value}(data);
    }

    function revertBytes(bytes memory errMsg) internal pure {
        if (errMsg.length != 0) {
            assembly {
                revert(add(32, errMsg), mload(errMsg))
            }
        }
        revert("CVC-empty-error");
    }

    receive() external payable {}
}
