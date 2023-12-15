// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.19;

import "./Set.sol";
import "./Events.sol";
import "./Errors.sol";
import "./TransientStorage.sol";
import "./interfaces/IEthereumVaultConnector.sol";
import "./interfaces/IVault.sol";
import "./interfaces/IERC1271.sol";

/// @title EthereumVaultConnector
/// @author Euler Labs (https://www.eulerlabs.com/)
/// @notice This contract implements the Ethereum Vault Connector.
contract EthereumVaultConnector is Events, Errors, TransientStorage, IEVC {
    using ExecutionContext for EC;
    using Set for SetStorage;

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                       CONSTANTS                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    string public constant name = "Ethereum Vault Connector";
    string public constant version = "1";

    bytes32 internal constant HASHED_NAME = keccak256(bytes(name));
    bytes32 internal constant HASHED_VERSION = keccak256(bytes(version));

    bytes32 internal constant PERMIT_TYPEHASH = keccak256(
        "Permit(address signer,uint256 nonceNamespace,uint256 nonce,uint256 deadline,uint256 value,bytes data)"
    );

    bytes32 internal constant TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    address internal constant ERC1820_REGISTRY = 0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24;

    uint256 internal immutable CACHED_CHAIN_ID;
    bytes32 internal immutable CACHED_DOMAIN_SEPARATOR;

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                        STORAGE                                            //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    // EVC implements controller isolation, meaning that unless in transient state, only one controller per account can
    // be enabled. However, this can lead to a suboptimal user experience. In the event a user wants to have multiple
    // controllers enabled, a separate wallet must be created and funded. Although there is nothing wrong with having
    // many accounts within the same wallet, this can be a bad experience. In order to improve on this, EVC supports
    // the concept of an owner that owns 256 accounts within EVC.

    // Every Ethereum address has 256 accounts in the EVC (including the primary account - called the owner).
    // Each account has an account ID from 0-255, where 0 is the owner account's ID. In order to compute the account
    // addresses, the account ID is treated as a uint256 and XORed (exclusive ORed) with the Ethereum address.
    // In order to record the owner of a group of 256 accounts, the EVC uses a definition of an address prefix.
    // An address prefix is a part of an address having the first 19 bytes common with any of the 256 account
    // addresses belonging to the same group.
    // account/152 -> prefix/152
    // To get an address prefix for the account, it's enough to take the account address and right shift it by 8 bits.

    // Yes, this reduces the security of addresses by 8 bits, but creating multiple addresses in the wallet also reduces
    // security: if somebody is trying to brute-force one of user's N>1 private keys, they have N times as many chances
    // of succeeding per guess. It has to be admitted that the EVC model is weaker because finding a private key for
    // an owner gives access to all accounts, but there is still a very comfortable security margin.

    mapping(uint152 addressPrefix => address owner) internal ownerLookup;

    mapping(uint152 addressPrefix => mapping(address operator => uint256 operatorBitField)) internal operatorLookup;

    mapping(uint152 addressPrefix => mapping(uint256 nonceNamespace => uint256 nonce)) internal nonceLookup;

    mapping(address account => SetStorage) internal accountCollaterals;

    mapping(address account => SetStorage) internal accountControllers;

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                CONSTRUCTOR, FALLBACKS                                     //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    constructor() {
        CACHED_CHAIN_ID = block.chainid;
        CACHED_DOMAIN_SEPARATOR = calculateDomainSeparator();
    }

    receive() external payable {}

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                       MODIFIERS                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice A modifier that allows only the address recorded as an owner of the address prefix to call the function.
    /// @dev The owner of an address prefix is an address that matches the address that has previously been recorded (or
    /// will be) as an owner in the ownerLookup. In case of the self-call in the permit() function, the EVC address
    /// becomes msg.sender hence the "true" caller address (that is permit message signer) is taken from the execution
    /// context.
    /// @param addressPrefix The address prefix for which it is checked whether the caller is the owner.
    modifier onlyOwner(uint152 addressPrefix) virtual {
        {
            // calculate a phantom address from the address prefix which can be used as an input to internal functions
            address account = address(uint160(addressPrefix) << 8);

            // EVC can only be msg.sender during the self-call in the permit() function. in that case,
            // the "true" sender address (that is the permit message signer) is taken from the execution context
            address msgSender = address(this) == msg.sender ? executionContext.getOnBehalfOfAccount() : msg.sender;

            if (haveCommonOwnerInternal(account, msgSender)) {
                address owner = getAccountOwnerInternal(account);

                if (owner == address(0)) {
                    setAccountOwnerInternal(account, msgSender);
                } else if (owner != msgSender) {
                    revert EVC_NotAuthorized();
                }
            } else {
                revert EVC_NotAuthorized();
            }
        }

        _;
    }

    /// @notice A modifier that allows only the owner or an operator of the account to call the function.
    /// @dev The owner of an account is an address that matches first 19 bytes of the account address and has been
    /// recorded (or will be) as an owner in the ownerLookup. An operator of an account is an address that has been
    /// authorized by the owner of an account to perform operations on behalf of the owner. In case of the self-call in
    /// the permit() function, the EVC address becomes msg.sender hence the "true" caller address (that is permit
    /// message signer) is taken from the execution context.
    /// @param account The address of the account for which it is checked whether the caller is the owner or an
    /// operator.
    modifier onlyOwnerOrOperator(address account) virtual {
        {
            // EVC can only be msg.sender during the self-call in the permit() function. in that case,
            // the "true" sender address (that is the permit message signer) is taken from the execution context
            address msgSender = address(this) == msg.sender ? executionContext.getOnBehalfOfAccount() : msg.sender;

            if (haveCommonOwnerInternal(account, msgSender)) {
                address owner = getAccountOwnerInternal(account);

                if (owner == address(0)) {
                    setAccountOwnerInternal(account, msgSender);
                } else if (owner != msgSender) {
                    revert EVC_NotAuthorized();
                }
            } else if (!isAccountOperatorAuthorizedInternal(account, msgSender)) {
                revert EVC_NotAuthorized();
            }
        }

        _;
    }

    /// @notice A modifier checks whether msg.sender is the only controller for the account.
    modifier onlyController(address account) {
        {
            uint256 numOfControllers = accountControllers[account].numElements;
            address controller = accountControllers[account].firstElement;

            if (numOfControllers != 1) {
                revert EVC_ControllerViolation();
            }

            if (controller != msg.sender) {
                revert EVC_NotAuthorized();
            }
        }

        _;
    }

    /// @notice A modifier that verifies whether account or vault status checks are re-entered as well as checks for
    /// impersonate re-entrancy.
    modifier nonReentrant() {
        {
            EC context = executionContext;

            if (context.areChecksInProgress()) {
                revert EVC_ChecksReentrancy();
            }

            if (context.isImpersonationInProgress()) {
                revert EVC_ImpersonateReentrancy();
            }
        }

        _;
    }

    /// @notice A modifier that verifies whether account or vault status checks are re-entered and sets the lock.
    modifier nonReentrantChecks() virtual {
        EC contextCache = executionContext;

        if (contextCache.areChecksInProgress()) {
            revert EVC_ChecksReentrancy();
        }

        executionContext = contextCache.setChecksInProgress().setOnBehalfOfAccount(address(0));

        _;

        executionContext = contextCache;
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                   PUBLIC FUNCTIONS                                        //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    // Execution internals

    /// @inheritdoc IEVC
    function getRawExecutionContext() external view returns (uint256 context) {
        context = EC.unwrap(executionContext);
    }

    /// @inheritdoc IEVC
    function getCurrentCallDepth() external view returns (uint256) {
        return executionContext.getCallDepth();
    }

    /// @inheritdoc IEVC
    function getCurrentOnBehalfOfAccount(address controllerToCheck)
        public
        view
        returns (address onBehalfOfAccount, bool controllerEnabled)
    {
        onBehalfOfAccount = executionContext.getOnBehalfOfAccount();

        // for safety, revert if no account has been authenticated
        if (onBehalfOfAccount == address(0)) {
            revert EVC_OnBehalfOfAccountNotAuthenticated();
        }

        controllerEnabled =
            controllerToCheck == address(0) ? false : accountControllers[onBehalfOfAccount].contains(controllerToCheck);
    }

    /// @inheritdoc IEVC
    function areChecksInProgress() external view returns (bool) {
        return executionContext.areChecksInProgress();
    }

    /// @inheritdoc IEVC
    function isImpersonationInProgress() external view returns (bool) {
        return executionContext.isImpersonationInProgress();
    }

    /// @inheritdoc IEVC
    function isOperatorAuthenticated() external view returns (bool) {
        return executionContext.isOperatorAuthenticated();
    }

    /// @inheritdoc IEVC
    function isSimulationInProgress() external view returns (bool) {
        return executionContext.isSimulationInProgress();
    }

    // Owners and operators

    /// @inheritdoc IEVC
    function haveCommonOwner(address account, address otherAccount) external pure returns (bool) {
        return haveCommonOwnerInternal(account, otherAccount);
    }

    /// @inheritdoc IEVC
    function getAddressPrefix(address account) external pure returns (uint152) {
        return getAddressPrefixInternal(account);
    }

    /// @inheritdoc IEVC
    function getAccountOwner(address account) external view returns (address owner) {
        owner = getAccountOwnerInternal(account);

        if (owner == address(0)) revert EVC_AccountOwnerNotRegistered();
    }

    /// @inheritdoc IEVC
    function getNonce(uint152 addressPrefix, uint256 nonceNamespace) external view returns (uint256) {
        return nonceLookup[addressPrefix][nonceNamespace];
    }

    /// @inheritdoc IEVC
    function getOperator(uint152 addressPrefix, address operator) external view returns (uint256) {
        return operatorLookup[addressPrefix][operator];
    }

    /// @inheritdoc IEVC
    function isAccountOperatorAuthorized(address account, address operator) external view returns (bool) {
        return isAccountOperatorAuthorizedInternal(account, operator);
    }

    /// @inheritdoc IEVC
    function setNonce(
        uint152 addressPrefix,
        uint256 nonceNamespace,
        uint256 nonce
    ) public payable virtual onlyOwner(addressPrefix) {
        if (nonceLookup[addressPrefix][nonceNamespace] >= nonce) {
            revert EVC_InvalidNonce();
        }

        nonceLookup[addressPrefix][nonceNamespace] = nonce;

        unchecked {
            nonce -= 1;
        }

        emit NonceUsed(addressPrefix, nonce);
    }

    /// @inheritdoc IEVC
    function setOperator(
        uint152 addressPrefix,
        address operator,
        uint256 operatorBitField
    ) public payable virtual onlyOwner(addressPrefix) {
        // if EVC is msg.sender (during the self-call in the permit() function), the owner address will
        // be taken from the storage which must be storing the correct owner address
        address owner = address(this) == msg.sender ? ownerLookup[addressPrefix] : msg.sender;

        // the operator can neither be zero address nor be the EVC nor can belong to one of 256 accounts of the owner
        if (operator == address(0) || operator == address(this) || haveCommonOwnerInternal(owner, operator)) {
            revert EVC_InvalidAddress();
        }

        if (operatorLookup[addressPrefix][operator] == operatorBitField) {
            revert EVC_InvalidOperatorStatus();
        } else {
            operatorLookup[addressPrefix][operator] = operatorBitField;

            emit OperatorStatus(addressPrefix, operator, operatorBitField);
        }
    }

    /// @inheritdoc IEVC
    function setAccountOperator(
        address account,
        address operator,
        bool authorized
    ) public payable virtual onlyOwnerOrOperator(account) {
        // if EVC is msg.sender (during the self-call in the permit() function), it won't have the common owner
        // with the account as it would mean that the EVC itself signed the ERC-1271 message which is not
        // possible. hence in that case, the owner address will be taken from the storage which
        // must be storing the correct owner address
        address owner = haveCommonOwnerInternal(account, msg.sender) ? msg.sender : getAccountOwnerInternal(account);

        // if EVC is msg.sender (during the self-call in the permit() function), it acts as if it
        // was an owner, meaning it can authorize and deauthorize operators as per signed data.
        // if it's an operator calling, it can only make changes for itself hence must be equal to msg.sender
        if (owner != msg.sender && operator != msg.sender && address(this) != msg.sender) {
            revert EVC_NotAuthorized();
        }

        // the operator can neither be zero address nor be the EVC nor can belong to one of 256 accounts of the owner
        if (operator == address(0) || operator == address(this) || haveCommonOwnerInternal(owner, operator)) {
            revert EVC_InvalidAddress();
        }

        uint152 addressPrefix = getAddressPrefixInternal(account);
        uint256 bitMask = 1 << (uint160(owner) ^ uint160(account));
        uint256 oldOperatorBitField = operatorLookup[addressPrefix][operator];
        uint256 newOperatorBitField = authorized ? oldOperatorBitField | bitMask : oldOperatorBitField & ~bitMask;

        if (oldOperatorBitField == newOperatorBitField) {
            revert EVC_InvalidOperatorStatus();
        } else {
            operatorLookup[addressPrefix][operator] = newOperatorBitField;

            emit OperatorStatus(addressPrefix, operator, newOperatorBitField);
        }
    }

    // Collaterals management

    /// @inheritdoc IEVC
    function getCollaterals(address account) external view returns (address[] memory) {
        return accountCollaterals[account].get();
    }

    /// @inheritdoc IEVC
    function isCollateralEnabled(address account, address vault) external view returns (bool) {
        return accountCollaterals[account].contains(vault);
    }

    /// @inheritdoc IEVC
    function enableCollateral(
        address account,
        address vault
    ) public payable virtual nonReentrant onlyOwnerOrOperator(account) {
        if (vault == address(this)) revert EVC_InvalidAddress();

        if (accountCollaterals[account].insert(vault)) {
            emit CollateralStatus(account, vault, true);
        }
        requireAccountStatusCheck(account);
    }

    /// @inheritdoc IEVC
    function disableCollateral(
        address account,
        address vault
    ) public payable virtual nonReentrant onlyOwnerOrOperator(account) {
        if (accountCollaterals[account].remove(vault)) {
            emit CollateralStatus(account, vault, false);
        }
        requireAccountStatusCheck(account);
    }

    /// @inheritdoc IEVC
    function reorderCollaterals(
        address account,
        uint8 index1,
        uint8 index2
    ) public payable virtual nonReentrant onlyOwnerOrOperator(account) {
        accountCollaterals[account].reorder(index1, index2);
        requireAccountStatusCheck(account);
    }

    // Controllers management

    /// @inheritdoc IEVC
    function getControllers(address account) external view returns (address[] memory) {
        return accountControllers[account].get();
    }

    /// @inheritdoc IEVC
    function isControllerEnabled(address account, address vault) external view returns (bool) {
        return accountControllers[account].contains(vault);
    }

    /// @inheritdoc IEVC
    function enableController(
        address account,
        address vault
    ) public payable virtual nonReentrant onlyOwnerOrOperator(account) {
        if (vault == address(this)) revert EVC_InvalidAddress();

        if (accountControllers[account].insert(vault)) {
            emit ControllerStatus(account, vault, true);
        }
        requireAccountStatusCheck(account);
    }

    /// @inheritdoc IEVC
    function disableController(address account) public payable virtual nonReentrant {
        if (accountControllers[account].remove(msg.sender)) {
            emit ControllerStatus(account, msg.sender, false);
        }
        requireAccountStatusCheck(account);
    }

    // Permit

    /// @inheritdoc IEVC
    function permit(
        address signer,
        uint256 nonceNamespace,
        uint256 nonce,
        uint256 deadline,
        uint256 value,
        bytes calldata data,
        bytes calldata signature
    ) public payable virtual nonReentrant {
        // cannot be called within the self-call of the permit(); can occur for nested permit() calls
        if (address(this) == msg.sender) {
            revert EVC_NotAuthorized();
        }

        uint152 addressPrefix = getAddressPrefixInternal(signer);

        if (signer == address(0) || !isSignerValid(signer)) {
            revert EVC_InvalidAddress();
        }

        uint256 currentNonce = nonceLookup[addressPrefix][nonceNamespace];

        if (currentNonce == type(uint256).max || currentNonce != nonce) {
            revert EVC_InvalidNonce();
        }

        unchecked {
            nonceLookup[addressPrefix][nonceNamespace] = currentNonce + 1;
        }

        if (deadline < block.timestamp) {
            revert EVC_InvalidTimestamp();
        }

        if (data.length == 0) {
            revert EVC_InvalidData();
        }

        bytes32 permitHash = getPermitHash(signer, nonceNamespace, nonce, deadline, value, data);

        if (
            signer != recoverECDSASigner(permitHash, signature)
                && !isValidERC1271Signature(signer, permitHash, signature)
        ) {
            revert EVC_NotAuthorized();
        }

        emit NonceUsed(addressPrefix, nonce);

        // EVC address becomes msg.sender for the duration this self-call
        (bool success, bytes memory result) = callWithContextInternal(address(this), signer, value, data);

        if (!success) {
            revertBytes(result);
        }
    }

    // Recover remaining ETH

    /// @inheritdoc IEVC
    function recoverRemainingETH(address recipient)
        public
        payable
        virtual
        nonReentrant
        onlyOwnerOrOperator(recipient)
    {
        // to prevent losing ETH, the recipient cannot be an account other than the registered owner
        if (getAccountOwnerInternal(recipient) != recipient) {
            revert EVC_InvalidAddress();
        }

        // callWithContextInternal is used here to properly set the context for the sake of fallback
        // functions that are receiving ETH. msg.data[:0] is a trick to pass empty calldata
        (bool success, bytes memory result) =
            callWithContextInternal(recipient, recipient, type(uint256).max, msg.data[:0]);

        if (!success) {
            revertBytes(result);
        }
    }

    // Calls forwarding

    /// @inheritdoc IEVC
    function callback(
        address onBehalfOfAccount,
        uint256 value,
        bytes calldata data
    ) public payable virtual nonReentrant returns (bytes memory result) {
        // cannot be called within the self-call of the permit()
        if (address(this) == msg.sender) {
            revert EVC_NotAuthorized();
        }

        EC contextCache = executionContext;
        executionContext = contextCache.increaseCallDepth();

        // call back into the msg.sender with the context set
        bool success;
        (success, result) = callWithContextInternal(msg.sender, onBehalfOfAccount, value, data);

        if (!success) {
            revertBytes(result);
        }

        restoreExecutionContext(contextCache);
    }

    /// @inheritdoc IEVC
    function call(
        address targetContract,
        address onBehalfOfAccount,
        uint256 value,
        bytes calldata data
    ) public payable virtual nonReentrant returns (bytes memory result) {
        if (address(this) == targetContract) {
            revert EVC_InvalidAddress();
        }

        EC contextCache = executionContext;
        executionContext = contextCache.increaseCallDepth();

        bool success;
        (success, result) = callInternal(targetContract, onBehalfOfAccount, value, data);

        if (!success) {
            revertBytes(result);
        }

        restoreExecutionContext(contextCache);
    }

    /// @inheritdoc IEVC
    function impersonate(
        address targetCollateral,
        address onBehalfOfAccount,
        uint256 value,
        bytes calldata data
    ) public payable virtual nonReentrant returns (bytes memory result) {
        if (address(this) == targetCollateral || msg.sender == targetCollateral) {
            revert EVC_InvalidAddress();
        }

        EC contextCache = executionContext;
        executionContext = contextCache.increaseCallDepth().setImpersonationInProgress();

        bool success;
        (success, result) = impersonateInternal(targetCollateral, onBehalfOfAccount, value, data);

        if (!success) {
            revertBytes(result);
        }

        restoreExecutionContext(contextCache);
    }

    /// @inheritdoc IEVC
    function batch(BatchItem[] calldata items) public payable virtual nonReentrant {
        EC contextCache = executionContext;
        executionContext = contextCache.increaseCallDepth();

        batchInternal(items);

        restoreExecutionContext(contextCache);
    }

    // Simulations

    /// @inheritdoc IEVC
    function batchRevert(BatchItem[] calldata items) public payable virtual nonReentrant {
        BatchItemResult[] memory batchItemsResult;
        StatusCheckResult[] memory accountsStatusCheckResult;
        StatusCheckResult[] memory vaultsStatusCheckResult;

        EC contextCache = executionContext;

        if (contextCache.getCallDepth() > 0) {
            revert EVC_SimulationBatchNested();
        }

        executionContext = contextCache.increaseCallDepth().setSimulationInProgress();

        batchItemsResult = batchInternalWithResult(items);

        executionContext = contextCache.setChecksInProgress();

        accountsStatusCheckResult = checkStatusAllWithResult(SetType.Account);
        vaultsStatusCheckResult = checkStatusAllWithResult(SetType.Vault);

        executionContext = contextCache;

        revert EVC_RevertedBatchResult(batchItemsResult, accountsStatusCheckResult, vaultsStatusCheckResult);
    }

    /// @inheritdoc IEVC
    function batchSimulation(BatchItem[] calldata items)
        public
        payable
        virtual
        returns (
            BatchItemResult[] memory batchItemsResult,
            StatusCheckResult[] memory accountsStatusCheckResult,
            StatusCheckResult[] memory vaultsStatusCheckResult
        )
    {
        (bool success, bytes memory result) = address(this).delegatecall(abi.encodeCall(this.batchRevert, items));

        if (success) {
            revert EVC_BatchPanic();
        } else if (bytes4(result) != EVC_RevertedBatchResult.selector) {
            revertBytes(result);
        }

        assembly {
            result := add(result, 4)
        }

        (batchItemsResult, accountsStatusCheckResult, vaultsStatusCheckResult) =
            abi.decode(result, (BatchItemResult[], StatusCheckResult[], StatusCheckResult[]));
    }

    // Account Status Check

    /// @inheritdoc IEVC
    function isAccountStatusCheckDeferred(address account) external view returns (bool) {
        return accountStatusChecks.contains(account);
    }

    /// @inheritdoc IEVC
    function requireAccountStatusCheck(address account) public payable virtual nonReentrantChecks {
        if (executionContext.areChecksDeferred()) {
            accountStatusChecks.insert(account);
        } else {
            requireAccountStatusCheckInternal(account);
        }
    }

    /// @inheritdoc IEVC
    function requireAccountStatusCheckNow(address account) public payable virtual nonReentrantChecks {
        accountStatusChecks.remove(account);
        requireAccountStatusCheckInternal(account);
    }

    /// @inheritdoc IEVC
    function requireAllAccountsStatusCheckNow() public payable virtual nonReentrantChecks {
        checkStatusAll(SetType.Account);
    }

    /// @inheritdoc IEVC
    function forgiveAccountStatusCheck(address account)
        public
        payable
        virtual
        nonReentrantChecks
        onlyController(account)
    {
        accountStatusChecks.remove(account);
    }

    // Vault Status Check

    /// @inheritdoc IEVC
    function isVaultStatusCheckDeferred(address vault) external view returns (bool) {
        return vaultStatusChecks.contains(vault);
    }

    /// @inheritdoc IEVC
    function requireVaultStatusCheck() public payable virtual nonReentrantChecks {
        if (executionContext.areChecksDeferred()) {
            vaultStatusChecks.insert(msg.sender);
        } else {
            requireVaultStatusCheckInternal(msg.sender);
        }
    }

    /// @inheritdoc IEVC
    function requireVaultStatusCheckNow() public payable virtual nonReentrantChecks {
        vaultStatusChecks.remove(msg.sender);
        requireVaultStatusCheckInternal(msg.sender);
    }

    /// @inheritdoc IEVC
    function requireAllVaultsStatusCheckNow() public payable virtual nonReentrantChecks {
        checkStatusAll(SetType.Vault);
    }

    /// @inheritdoc IEVC
    function forgiveVaultStatusCheck() public payable virtual nonReentrantChecks {
        vaultStatusChecks.remove(msg.sender);
    }

    /// @inheritdoc IEVC
    function requireAccountAndVaultStatusCheck(address account) public payable virtual nonReentrantChecks {
        if (executionContext.areChecksDeferred()) {
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

    function callWithContextInternal(
        address targetContract,
        address onBehalfOfAccount,
        uint256 value,
        bytes calldata data
    ) internal virtual returns (bool success, bytes memory result) {
        if (value == type(uint256).max) {
            value = address(this).balance;
        } else if (value > address(this).balance) {
            revert EVC_InvalidValue();
        }

        EC contextCache = executionContext;

        // EVC can only be msg.sender after the self-call in the permit() function. in that case,
        // the "true" sender address (that is the permit message signer) is taken from the execution context
        address msgSender = address(this) == msg.sender ? contextCache.getOnBehalfOfAccount() : msg.sender;

        emit CallWithContext(msgSender, targetContract, onBehalfOfAccount, bytes4(data));

        // set the onBehalfOfAccount in the execution context for the duration of the external call.
        // considering that the operatorAuthenticated is only meant to be observable by external
        // contracts, it is sufficient to set it here rather than in the onlyOwner and onlyOwnerOrOperator
        // modifiers.
        // apart from the usual scenario (when an owner operates on behalf of its account),
        // the operatorAuthenticated should be cleared when about to execute the permit self-call, callback,
        // or when the impersonation is in progress (in which case the operatorAuthenticated is not relevant)
        if (
            haveCommonOwnerInternal(onBehalfOfAccount, msgSender) || address(this) == targetContract
                || msg.sender == targetContract || contextCache.isImpersonationInProgress()
        ) {
            executionContext = contextCache.setOnBehalfOfAccount(onBehalfOfAccount).clearOperatorAuthenticated();
        } else {
            executionContext = contextCache.setOnBehalfOfAccount(onBehalfOfAccount).setOperatorAuthenticated();
        }

        (success, result) = targetContract.call{value: value}(data);

        executionContext = contextCache;
    }

    function callInternal(
        address targetContract,
        address onBehalfOfAccount,
        uint256 value,
        bytes calldata data
    ) internal virtual onlyOwnerOrOperator(onBehalfOfAccount) returns (bool success, bytes memory result) {
        if (msg.sender == targetContract || targetContract == ERC1820_REGISTRY) {
            revert EVC_InvalidAddress();
        }

        (success, result) = callWithContextInternal(targetContract, onBehalfOfAccount, value, data);
    }

    function impersonateInternal(
        address targetCollateral,
        address onBehalfOfAccount,
        uint256 value,
        bytes calldata data
    ) internal virtual onlyController(onBehalfOfAccount) returns (bool success, bytes memory result) {
        if (!accountCollaterals[onBehalfOfAccount].contains(targetCollateral)) {
            revert EVC_NotAuthorized();
        }

        (success, result) = callWithContextInternal(targetCollateral, onBehalfOfAccount, value, data);
    }

    function callBatchItemInternal(BatchItem calldata item) internal returns (bool success, bytes memory result) {
        if (item.targetContract == address(this)) {
            if (item.onBehalfOfAccount != address(0)) {
                revert EVC_InvalidAddress();
            }

            if (item.value != 0) {
                revert EVC_InvalidValue();
            }

            // delegatecall is used here to preserve msg.sender in order
            // to be able to perform authentication
            (success, result) = address(this).delegatecall(item.data);
        } else {
            (success, result) = callInternal(item.targetContract, item.onBehalfOfAccount, item.value, item.data);
        }
    }

    function batchInternal(BatchItem[] calldata items) internal {
        uint256 length = items.length;

        for (uint256 i; i < length;) {
            (bool success, bytes memory result) = callBatchItemInternal(items[i]);

            if (!success) {
                revertBytes(result);
            }

            unchecked {
                ++i;
            }
        }
    }

    function batchInternalWithResult(BatchItem[] calldata items)
        internal
        returns (BatchItemResult[] memory batchItemsResult)
    {
        uint256 length = items.length;
        batchItemsResult = new BatchItemResult[](length);

        for (uint256 i; i < length;) {
            (batchItemsResult[i].success, batchItemsResult[i].result) = callBatchItemInternal(items[i]);

            unchecked {
                ++i;
            }
        }
    }

    function checkAccountStatusInternal(address account) internal virtual returns (bool isValid, bytes memory result) {
        uint256 numOfControllers = accountControllers[account].numElements;
        address controller = accountControllers[account].firstElement;

        if (numOfControllers == 0) return (true, "");
        else if (numOfControllers > 1) revert EVC_ControllerViolation();

        bool success;
        (success, result) =
            controller.call(abi.encodeCall(IVault.checkAccountStatus, (account, accountCollaterals[account].get())));

        isValid = success && result.length == 32
            && abi.decode(result, (bytes32)) == bytes32(IVault.checkAccountStatus.selector);
    }

    function requireAccountStatusCheckInternal(address account) internal virtual {
        (bool isValid, bytes memory result) = checkAccountStatusInternal(account);

        if (!isValid) {
            revertBytes(result);
        }
    }

    function checkVaultStatusInternal(address vault) internal returns (bool isValid, bytes memory result) {
        bool success;
        (success, result) = vault.call(abi.encodeCall(IVault.checkVaultStatus, ()));

        isValid =
            success && result.length == 32 && abi.decode(result, (bytes32)) == bytes32(IVault.checkVaultStatus.selector);
    }

    function requireVaultStatusCheckInternal(address vault) internal virtual {
        (bool isValid, bytes memory result) = checkVaultStatusInternal(vault);

        if (!isValid) {
            revertBytes(result);
        }
    }

    function checkStatusAll(SetType setType) internal virtual {
        setType == SetType.Account
            ? accountStatusChecks.forEachAndClear(requireAccountStatusCheckInternal)
            : vaultStatusChecks.forEachAndClear(requireVaultStatusCheckInternal);
    }

    function checkStatusAllWithResult(SetType setType)
        internal
        virtual
        returns (StatusCheckResult[] memory checksResult)
    {
        bytes[] memory callbackResult = setType == SetType.Account
            ? accountStatusChecks.forEachAndClearWithResult(checkAccountStatusInternal)
            : vaultStatusChecks.forEachAndClearWithResult(checkVaultStatusInternal);

        uint256 length = callbackResult.length;
        checksResult = new StatusCheckResult[](length);

        for (uint256 i; i < length;) {
            (address checkedAddress, bool isValid, bytes memory result) =
                abi.decode(callbackResult[i], (address, bool, bytes));
            checksResult[i] = StatusCheckResult(checkedAddress, isValid, result);

            unchecked {
                ++i;
            }
        }
    }

    function restoreExecutionContext(EC contextCache) internal virtual {
        if (!contextCache.areChecksDeferred()) {
            executionContext = contextCache.setChecksInProgress();

            checkStatusAll(SetType.Account);
            checkStatusAll(SetType.Vault);
        }

        executionContext = contextCache;
    }

    // Permit-related functions

    function isSignerValid(address signer) internal pure returns (bool) {
        // not valid if the signer address falls into any of the precompiles/predeploys
        // addresses space (depends on the chain ID).
        // IMPORTANT: revisit this logic when deploying on chains other than the Ethereum mainnet
        return !haveCommonOwnerInternal(signer, address(0));
    }

    function getPermitHash(
        address signer,
        uint256 nonceNamespace,
        uint256 nonce,
        uint256 deadline,
        uint256 value,
        bytes calldata data
    ) internal view returns (bytes32 permitHash) {
        bytes32 domainSeparator =
            block.chainid == CACHED_CHAIN_ID ? CACHED_DOMAIN_SEPARATOR : calculateDomainSeparator();

        bytes32 structHash =
            keccak256(abi.encode(PERMIT_TYPEHASH, signer, nonceNamespace, nonce, deadline, value, keccak256(data)));

        // This code overwrites the two most significant bytes of the free memory pointer,
        // and restores them to 0 after
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
    function recoverECDSASigner(bytes32 hash, bytes memory signature) internal pure returns (address signer) {
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
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
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
        if (signer.code.length == 0) return false;

        (bool success, bytes memory result) =
            signer.staticcall(abi.encodeCall(IERC1271.isValidSignature, (hash, signature)));

        isValid = success && result.length == 32
            && abi.decode(result, (bytes32)) == bytes32(IERC1271.isValidSignature.selector);
    }

    function calculateDomainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(TYPE_HASH, HASHED_NAME, HASHED_VERSION, block.chainid, address(this)));
    }

    // Auxiliary functions

    function haveCommonOwnerInternal(address account, address otherAccount) internal pure returns (bool result) {
        assembly {
            result := lt(xor(account, otherAccount), 0x100)
        }
    }

    function getAddressPrefixInternal(address account) internal pure returns (uint152) {
        return uint152(uint160(account) >> 8);
    }

    function getAccountOwnerInternal(address account) internal view returns (address) {
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
        uint256 bitMask = 1 << (uint160(owner) ^ uint160(account));

        return operatorLookup[addressPrefix][operator] & bitMask != 0;
    }

    function setAccountOwnerInternal(address account, address owner) internal {
        uint152 addressPrefix = getAddressPrefixInternal(account);
        ownerLookup[addressPrefix] = owner;
        emit OwnerRegistered(addressPrefix, owner);
    }

    function revertBytes(bytes memory errMsg) internal pure {
        if (errMsg.length != 0) {
            assembly {
                revert(add(32, errMsg), mload(errMsg))
            }
        }
        revert EVC_EmptyError();
    }
}
