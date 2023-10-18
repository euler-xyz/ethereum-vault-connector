// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "./Set.sol";
import "./TransientStorage.sol";
import "./interfaces/ICreditVaultConnector.sol";
import "./interfaces/ICreditVault.sol";
import "./interfaces/IERC1271.sol";

contract CreditVaultConnector is TransientStorage, ICVC {
    using ExecutionContext for EC;
    using Set for SetStorage;

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                       CONSTANTS                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    string public constant name = "Credit Vault Connector";
    string public constant version = "1";

    bytes32 public constant PERMIT_TYPEHASH =
        keccak256(
            "Permit(address signer,uint nonceNamespace,uint nonce,uint deadline,bytes data)"
        );

    bytes32 internal constant TYPE_HASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    bytes32 internal constant HASHED_NAME = keccak256(bytes(name));
    bytes32 internal constant HASHED_VERSION = keccak256(bytes(version));

    address internal constant ERC1820_REGISTRY =
        0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24;

    uint256 internal immutable CACHED_CHAIN_ID;
    bytes32 internal immutable CACHED_DOMAIN_SEPARATOR;

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                        STORAGE                                            //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    mapping(address account => SetStorage) internal accountCollaterals;
    mapping(address account => SetStorage) internal accountControllers;

    // Every Ethereum address has 256 accounts in the CVC (including the primary account - called the owner).
    // Each account has an account ID from 0-255, where 0 is the owner account's ID. In order to compute the account
    // addresses, the account ID is treated as a uint and XORed (exclusive ORed) with the Ethereum address.
    // In order to record the owner of a group of 256 accounts, the CVC uses a definition of a address prefix.
    // An address prefix is a part of an address having the first 19 bytes common with any of the 256 account
    // addresses belonging to the same group.
    // account/152 -> prefix/152
    // To get an address prefix for the account, it's enough to take the account address and right shift it by 8 bits.

    mapping(uint152 addressPrefix => address owner) internal ownerLookup;

    mapping(uint152 addressPrefix => mapping(uint nonceNamespace => uint nonce))
        internal nonceLookup;

    mapping(uint152 addressPrefix => mapping(address operator => uint accountBitField))
        internal operatorLookup;

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                        EVENTS                                             //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    event OwnerRegistered(uint152 indexed addressPrefix, address indexed owner);
    event NonceUsed(uint152 indexed addressPrefix, uint indexed nonce);
    event OperatorStatus(
        address indexed account,
        address indexed operator,
        bool indexed authorized
    );
    event ControllerStatus(
        address indexed account,
        address indexed controller,
        bool indexed enabled
    );

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                         ERRORS                                            //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    error CVC_NotAuthorized();
    error CVC_AccountOwnerNotRegistered();
    error CVC_InvalidNonce();
    error CVC_InvalidAddress();
    error CVC_InvalidTimestamp();
    error CVC_InvalidData();
    error CVC_ChecksReentrancy();
    error CVC_ImpersonateReentrancy();
    error CVC_BatchDepthViolation();
    error CVC_ControllerViolation();
    error CVC_RevertedBatchResult(
        BatchItemResult[] batchItemsResult,
        BatchItemResult[] accountsStatusResult,
        BatchItemResult[] vaultsStatusResult
    );
    error CVC_BatchPanic();
    error CVC_EmptyError();

    constructor() {
        CACHED_CHAIN_ID = block.chainid;
        CACHED_DOMAIN_SEPARATOR = calculateDomainSeparator();
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                       MODIFIERS                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice A modifier that allows only the owner of the account to call the function.
    /// @dev The owner of an account is an address that matches first 19 bytes of the account address and has been recorded (or will be) as an owner in the ownerLookup. In case of the self-call in the permit() function, the CVC address becomes msg.sender hence the "true" caller address (that is permit message signer) is taken from the execution context.
    /// @param account The address of the account for which it is checked whether the caller is the owner.
    modifier onlyOwner(address account) virtual {
        {
            // CVC can only be msg.sender during the self-call in the permit() function. in that case,
            // the "true" sender address (that is the permit message signer) is taken from the execution context
            address msgSender = address(this) == msg.sender
                ? executionContext.getOnBehalfOfAccount()
                : msg.sender;

            if (haveCommonOwnerInternal(account, msgSender)) {
                address owner = getAccountOwnerInternal(account);

                if (owner == address(0)) {
                    setAccountOwnerInternal(account, msgSender);
                } else if (owner != msgSender) {
                    revert CVC_NotAuthorized();
                }
            } else {
                revert CVC_NotAuthorized();
            }
        }

        _;
    }

    /// @notice A modifier that allows only the owner or an operator of the account to call the function.
    /// @dev The owner of an account is an address that matches first 19 bytes of the account address and has been recorded (or will be) as an owner in the ownerLookup. An operator of an account is an address that has been authorized by the owner of an account to perform operations on behalf of the owner. In case of the self-call in the permit() function, the CVC address becomes msg.sender hence the "true" caller address (that is permit message signer) is taken from the execution context.
    /// @param account The address of the account for which it is checked whether the caller is the owner or an operator.
    modifier onlyOwnerOrOperator(address account) virtual {
        {
            // CVC can only be msg.sender during the self-call in the permit() function. in that case,
            // the "true" sender address (that is the permit message signer) is taken from the execution context
            address msgSender = address(this) == msg.sender
                ? executionContext.getOnBehalfOfAccount()
                : msg.sender;

            if (haveCommonOwnerInternal(account, msgSender)) {
                address owner = getAccountOwnerInternal(account);

                if (owner == address(0)) {
                    setAccountOwnerInternal(account, msgSender);
                } else if (owner != msgSender) {
                    revert CVC_NotAuthorized();
                }
            } else if (
                !isAccountOperatorAuthorizedInternal(account, msgSender)
            ) {
                revert CVC_NotAuthorized();
            }
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
            EC context = executionContext;

            if (context.areChecksInProgress()) {
                revert CVC_ChecksReentrancy();
            }

            if (context.isImpersonationInProgress()) {
                revert CVC_ImpersonateReentrancy();
            }
        }

        _;
    }

    /// @notice A modifier that verifies whether account or vault status checks are reentered and sets the lock.
    modifier nonReentrantChecks() virtual {
        EC contextCache = executionContext;

        if (contextCache.areChecksInProgress()) {
            revert CVC_ChecksReentrancy();
        }

        executionContext = contextCache.setChecksInProgress();

        _;

        executionContext = contextCache;
    }

    /// @notice A modifier that sets onBehalfOfAccount in the execution context to the specified account.
    /// @dev Should be used as the last modifier in the function so that context is limited only to the function body.
    modifier onBehalfOfAccountContext(address account) virtual {
        EC contextCache = executionContext;

        executionContext = contextCache.setOnBehalfOfAccount(account);

        _;

        executionContext = contextCache;
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                   PUBLIC FUNCTIONS                                        //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    // Execution internals

    /// @inheritdoc ICVC
    function getRawExecutionContext() external view returns (uint context) {
        context = EC.unwrap(executionContext);
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
        EC context = executionContext;

        // execution context must be checks reentrancy protected because on behalf of account
        // might be inconsistent while checks are in progress
        if (context.areChecksInProgress()) {
            revert CVC_ChecksReentrancy();
        }

        onBehalfOfAccount = context.getOnBehalfOfAccount();

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
    function getAddressPrefix(address account) external pure returns (uint152) {
        return getAddressPrefixInternal(account);
    }

    /// @inheritdoc ICVC
    function getAccountOwner(
        address account
    ) external view returns (address owner) {
        owner = getAccountOwnerInternal(account);

        if (owner == address(0)) revert CVC_AccountOwnerNotRegistered();
    }

    /// @inheritdoc ICVC
    function getNonce(
        address account,
        uint nonceNamespace
    ) external view returns (uint) {
        uint152 addressPrefix = getAddressPrefixInternal(account);
        return nonceLookup[addressPrefix][nonceNamespace];
    }

    /// @inheritdoc ICVC
    function isAccountOperatorAuthorized(
        address account,
        address operator
    ) external view returns (bool authorized) {
        return isAccountOperatorAuthorizedInternal(account, operator);
    }

    /// @inheritdoc ICVC
    function setNonce(
        address account,
        uint nonceNamespace,
        uint nonce
    ) public payable virtual onlyOwner(account) {
        uint152 addressPrefix = getAddressPrefixInternal(account);

        if (nonceLookup[addressPrefix][nonceNamespace] >= nonce) {
            revert CVC_InvalidNonce();
        }

        nonceLookup[addressPrefix][nonceNamespace] = nonce;
        emit NonceUsed(addressPrefix, nonce);
    }

    /// @inheritdoc ICVC
    function setAccountOperator(
        address account,
        address operator,
        bool authorized
    ) public payable virtual onlyOwnerOrOperator(account) {
        // if CVC is msg.sender (during the self-call in the permit() function), it won't have the common owner
        // with the account as it would mean that the CVC itself signed the ERC-1271 message which is not
        // possible. hence in that case, the owner address will always be taken from the storage which
        // must be storing the correct owner address
        address owner = haveCommonOwnerInternal(account, msg.sender)
            ? msg.sender
            : getAccountOwnerInternal(account);

        // the operator can neither be zero address nor can belong to one of 256 accounts of the owner
        if (
            operator == address(0) || haveCommonOwnerInternal(owner, operator)
        ) {
            revert CVC_InvalidAddress();
        }

        // if CVC is msg.sender (during the self-call in the permit() function), it acts as if it
        // was an owner, meaning it can authorize and deauthorize operators as per signed data.
        // if it's an operator calling, it can only make changes for itself
        if (
            owner != msg.sender &&
            operator != msg.sender &&
            address(this) != msg.sender
        ) {
            revert CVC_NotAuthorized();
        }

        setAccountOperatorInternal(account, operator, authorized);
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
        if (vault == address(this)) revert CVC_InvalidAddress();

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
        if (vault == address(this)) revert CVC_InvalidAddress();

        if (accountControllers[account].insert(vault)) {
            emit ControllerStatus(account, vault, true);
        }
        requireAccountStatusCheck(account);
    }

    /// @inheritdoc ICVC
    function disableController(
        address account
    ) public payable virtual nonReentrant {
        if (accountControllers[account].remove(msg.sender)) {
            emit ControllerStatus(account, msg.sender, false);
        }
        requireAccountStatusCheck(account);
    }

    // Call forwarding

    /// @inheritdoc ICVC
    function call(
        address targetContract,
        address onBehalfOfAccount,
        bytes calldata data
    ) public payable virtual nonReentrant {
        if (targetContract == address(this)) revert CVC_InvalidAddress();

        uint value = executionContext.isInBatch() ? 0 : msg.value;

        (bool success, bytes memory result) = callInternal(
            targetContract,
            onBehalfOfAccount,
            value,
            data
        );

        if (!success) {
            revertBytes(result);
        }
    }

    /// @inheritdoc ICVC
    function impersonate(
        address targetContract,
        address onBehalfOfAccount,
        bytes calldata data
    ) public payable virtual nonReentrant {
        if (targetContract == address(this)) revert CVC_InvalidAddress();

        EC contextCache = executionContext;

        uint value = contextCache.isInBatch() ? 0 : msg.value;

        executionContext = contextCache.setImpersonationInProgress();

        (bool success, bytes memory result) = impersonateInternal(
            targetContract,
            onBehalfOfAccount,
            value,
            data
        );

        executionContext = contextCache;

        if (!success) {
            revertBytes(result);
        }
    }

    /// @inheritdoc ICVC
    function permit(
        address signer,
        uint nonceNamespace,
        uint nonce,
        uint deadline,
        bytes calldata data,
        bytes calldata signature
    ) public payable virtual nonReentrant {
        uint152 addressPrefix = getAddressPrefixInternal(signer);

        if (signer == address(0)) {
            revert CVC_InvalidAddress();
        }

        if (++nonceLookup[addressPrefix][nonceNamespace] != nonce) {
            revert CVC_InvalidNonce();
        }

        if (deadline < block.timestamp) {
            revert CVC_InvalidTimestamp();
        }

        if (data.length == 0) {
            revert CVC_InvalidData();
        }

        bytes32 permitHash = getPermitHash(
            signer,
            nonceNamespace,
            nonce,
            deadline,
            data
        );

        if (
            signer != recoverECDSASigner(permitHash, signature) &&
            !isValidERC1271Signature(signer, permitHash, signature)
        ) {
            revert CVC_NotAuthorized();
        }

        emit NonceUsed(addressPrefix, nonce);

        uint value = executionContext.isInBatch() ? 0 : msg.value;

        // CVC address becomes msg.sender for the duration this self-call
        (bool success, bytes memory result) = callPermitDataInternal(
            address(this),
            signer,
            value,
            data
        );

        if (!success) {
            revertBytes(result);
        }
    }

    // Batching

    /// @inheritdoc ICVC
    function batch(
        BatchItem[] calldata items
    ) public payable virtual nonReentrant {
        EC contextCache = executionContext;

        if (contextCache.isBatchDepthExceeded()) {
            revert CVC_BatchDepthViolation();
        }

        executionContext = contextCache.increaseBatchDepth();

        batchInternal(items, false);

        if (!contextCache.isInBatch()) {
            executionContext = contextCache.setChecksInProgress();

            checkStatusAll(SetType.Account, false);
            checkStatusAll(SetType.Vault, false);
        }

        executionContext = contextCache;
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
        EC contextCache = executionContext;

        if (contextCache.isBatchDepthExceeded()) {
            revert CVC_BatchDepthViolation();
        }

        executionContext = contextCache.increaseBatchDepth();

        batchItemsResult = batchInternal(items, true);

        // batch depth does not have to be explicitly decreased here as we're using cached context

        if (!contextCache.isInBatch()) {
            executionContext = contextCache.setChecksInProgress();

            accountsStatusResult = checkStatusAll(SetType.Account, true);
            vaultsStatusResult = checkStatusAll(SetType.Vault, true);
        }

        executionContext = contextCache;

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
        if (executionContext.isInBatch()) {
            accountStatusChecks.insert(account);
        } else {
            requireAccountStatusCheckInternal(account);
        }
    }

    /// @inheritdoc ICVC
    function requireAccountsStatusCheck(
        address[] calldata accounts
    ) public payable virtual nonReentrantChecks {
        bool inBatch = executionContext.isInBatch();
        uint length = accounts.length;
        for (uint i; i < length; ) {
            if (inBatch) {
                accountStatusChecks.insert(accounts[i]);
            } else {
                requireAccountStatusCheckInternal(accounts[i]);
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
        if (executionContext.isInBatch()) {
            vaultStatusChecks.insert(msg.sender);
        } else {
            requireVaultStatusCheckInternal(msg.sender);
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
        if (executionContext.isInBatch()) {
            accountStatusChecks.insert(account);
            vaultStatusChecks.insert(msg.sender);
        } else {
            requireAccountStatusCheckInternal(account);
            requireVaultStatusCheckInternal(msg.sender);
        }
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
        onlyOwnerOrOperator(onBehalfOfAccount)
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
        virtual
        onlyController(onBehalfOfAccount)
        onBehalfOfAccountContext(onBehalfOfAccount)
        returns (bool success, bytes memory result)
    {
        if (!accountCollaterals[onBehalfOfAccount].contains(targetContract)) {
            revert CVC_NotAuthorized();
        }

        (success, result) = targetContract.call{value: value}(data);
    }

    function callPermitDataInternal(
        address targetContract,
        address signer,
        uint value,
        bytes calldata data
    )
        internal
        virtual
        onBehalfOfAccountContext(signer)
        returns (bool success, bytes memory result)
    {
        (success, result) = targetContract.call{value: value}(data);
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
                (success, result) = callInternal(
                    targetContract,
                    item.onBehalfOfAccount,
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
    ) internal virtual returns (bool isValid, bytes memory result) {
        uint numOfControllers = accountControllers[account].numElements;
        address controller = accountControllers[account].firstElement;

        if (numOfControllers == 0) return (true, "");
        else if (numOfControllers > 1) revert CVC_ControllerViolation();

        bool success;
        (success, result) = controller.call(
            abi.encodeCall(
                ICreditVault.checkAccountStatus,
                (account, accountCollaterals[account].get())
            )
        );

        if (
            success &&
            ICreditVault.checkAccountStatus.selector ==
            abi.decode(result, (bytes4))
        ) {
            isValid = true;
        }
    }

    function requireAccountStatusCheckInternal(
        address account
    ) internal virtual {
        (bool isValid, bytes memory result) = checkAccountStatusInternal(
            account
        );

        if (!isValid) {
            revertBytes(result);
        }
    }

    function checkVaultStatusInternal(
        address vault
    ) internal returns (bool isValid, bytes memory result) {
        bool success;
        (success, result) = vault.call(
            abi.encodeCall(ICreditVault.checkVaultStatus, ())
        );

        if (
            success &&
            ICreditVault.checkVaultStatus.selector ==
            abi.decode(result, (bytes4))
        ) {
            isValid = true;
        }
    }

    function requireVaultStatusCheckInternal(address vault) internal virtual {
        (bool isValid, bytes memory result) = checkVaultStatusInternal(vault);

        if (!isValid) {
            revertBytes(result);
        }
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
                (result[i].success, result[i].result) = checkStatus(
                    addressToCheck
                );
            } else {
                requireStatusCheck(addressToCheck);
            }

            unchecked {
                ++i;
            }
        }
    }

    // Permit-related functions

    function getPermitHash(
        address signer,
        uint nonceNamespace,
        uint nonce,
        uint deadline,
        bytes calldata data
    ) internal view returns (bytes32 permitHash) {
        bytes32 domainSeparator = block.chainid == CACHED_CHAIN_ID
            ? CACHED_DOMAIN_SEPARATOR
            : calculateDomainSeparator();

        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_TYPEHASH,
                signer,
                nonceNamespace,
                nonce,
                deadline,
                keccak256(data)
            )
        );

        assembly ("memory-safe") {
            mstore(0x00, "\x19\x01")
            mstore(0x02, domainSeparator)
            mstore(0x22, structHash)
            permitHash := keccak256(0x00, 0x42)
            mstore(0x22, 0)
        }
    }

    // Based on:
    // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol
    // Note that the function returns zero address if the signature is invalid hence the result always has to be
    // checked against address zero.
    function recoverECDSASigner(
        bytes32 hash,
        bytes memory signature
    ) internal pure returns (address signer) {
        if (signature.length != 65) return address(0);

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
            return address(0);
        }

        // return the signer address (note that it might be zero address)
        signer = ecrecover(hash, v, r, s);
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

    function calculateDomainSeparator() internal view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    TYPE_HASH,
                    HASHED_NAME,
                    HASHED_VERSION,
                    block.chainid,
                    address(this)
                )
            );
    }

    // Auxiliary functions

    function haveCommonOwnerInternal(
        address account,
        address otherAccount
    ) internal pure returns (bool res) {
        assembly {
            res := lt(xor(account, otherAccount), 0x100)
        }
    }

    function getAddressPrefixInternal(
        address account
    ) internal pure returns (uint152) {
        return uint152(uint160(account) >> 8);
    }

    function getAccountOwnerInternal(
        address account
    ) internal view returns (address) {
        uint152 addressPrefix = getAddressPrefixInternal(account);
        return ownerLookup[addressPrefix];
    }

    function isAccountOperatorAuthorizedInternal(
        address account,
        address operator
    ) internal view returns (bool isAuthorized) {
        address owner = getAccountOwnerInternal(account);

        // if the owner is not registered yet, it means that the operator couldn't have been authorized
        if (owner == address(0)) return false;

        uint152 addressPrefix = getAddressPrefixInternal(account);
        uint accountBit = uint160(owner) ^ uint160(account);
        uint accountBitMask = 1 << accountBit;

        return operatorLookup[addressPrefix][operator] & accountBitMask != 0;
    }

    function setAccountOwnerInternal(address account, address owner) internal {
        uint152 addressPrefix = getAddressPrefixInternal(account);
        ownerLookup[addressPrefix] = owner;
        emit OwnerRegistered(addressPrefix, owner);
    }

    function setAccountOperatorInternal(
        address account,
        address operator,
        bool authorized
    ) internal {
        address owner = getAccountOwnerInternal(account);
        uint152 addressPrefix = getAddressPrefixInternal(account);
        uint accountBit = uint160(owner) ^ uint160(account);
        uint accountBitMask = 1 << accountBit;
        uint accountBitField = operatorLookup[addressPrefix][operator];
        bool oldAuthorized = accountBitField & accountBitMask != 0;

        if (oldAuthorized != authorized) {
            operatorLookup[addressPrefix][operator] = authorized
                ? accountBitField | accountBitMask
                : accountBitField & ~accountBitMask;

            emit OperatorStatus(account, operator, authorized);
        }
    }

    function revertBytes(bytes memory errMsg) internal pure {
        if (errMsg.length != 0) {
            assembly {
                revert(add(32, errMsg), mload(errMsg))
            }
        }
        revert CVC_EmptyError();
    }

    receive() external payable {}
}
