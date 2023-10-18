// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "./CreditVaultConnectorScribble.sol";

contract CreditVaultConnectorEchidna is CreditVaultConnectorScribble {
    using ExecutionContext for EC;
    using Set for SetStorage;

    bool private inPermit;

    modifier onlyOwner(uint152 addressPrefix) override {
        assert(address(this) == msg.sender ? inPermit : true);

        {
            // calculate a phantom address from the address prefix which can be used as an input to internal functions
            address account = address(uint160(addressPrefix) << 8);

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

    modifier onlyOwnerOrOperator(address account) override {
        assert(address(this) == msg.sender ? inPermit : true);

        {
            // CVC can only be msg.sender during the self-call in the permit() function. in that case,
            // the "true" sender address (that is the permit message signer) is taken from the execution context
            address msgSender = address(this) == msg.sender
                ? executionContext.getOnBehalfOfAccount()
                : msg.sender;

            assert(msgSender != address(0));

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

    modifier nonReentrantChecks() override {
        EC context = executionContext;

        if (context.areChecksInProgress()) {
            revert CVC_ChecksReentrancy();
        }

        executionContext = context.setChecksInProgress();

        _;

        // verify if cached context value can be reused
        assert(
            EC.unwrap(executionContext) ==
                EC.unwrap(context.setChecksInProgress())
        );

        executionContext = context;
    }

    modifier onBehalfOfAccountContext(address account) override {
        EC context = executionContext;

        executionContext = context.setOnBehalfOfAccount(account);

        _;

        // verify if cached context value can be reused
        assert(
            EC.unwrap(executionContext) ==
                EC.unwrap(context.setOnBehalfOfAccount(account))
        );

        executionContext = context;
    }

    function impersonate(
        address targetContract,
        address onBehalfOfAccount,
        bytes calldata data
    ) public payable override nonReentrant {
        // copied function body with inserted assertion
        if (targetContract == address(this)) revert CVC_InvalidAddress();

        EC context = executionContext;

        uint value = executionContext.isInBatch() ? 0 : msg.value;

        onBehalfOfAccount = onBehalfOfAccount == address(0)
            ? msg.sender
            : onBehalfOfAccount;

        executionContext = context.setImpersonationInProgress();

        (bool success, bytes memory result) = impersonateInternal(
            targetContract,
            onBehalfOfAccount,
            value,
            data
        );

        // verify if cached context value can be reused
        assert(
            EC.unwrap(executionContext) ==
                EC.unwrap(context.setImpersonationInProgress())
        );

        executionContext = context;

        if (!success) {
            revertBytes(result);
        }
    }

    function permit(
        address signer,
        uint nonceNamespace,
        uint nonce,
        uint deadline,
        bytes calldata data,
        bytes calldata signature
    ) public payable override nonReentrant {
        // copied function body with setting inPermit flag
        inPermit = true;

        uint152 addressPrefix = getAddressPrefixInternal(signer);

        if (signer == address(0)) {
            revert CVC_InvalidAddress();
        }

        if (++nonceLookup[addressPrefix][nonceNamespace] == nonce) {
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

        inPermit = false;
    }

    function batch(
        BatchItem[] calldata items
    ) public payable override nonReentrant {
        // copied function body with inserted assertion
        EC context = executionContext;

        if (context.isBatchDepthExceeded()) {
            revert CVC_BatchDepthViolation();
        }

        executionContext = context.increaseBatchDepth();

        batchInternal(items, false);

        // verify if cached context value can be reused
        assert(
            EC.unwrap(executionContext) ==
                EC.unwrap(context.increaseBatchDepth())
        );

        if (!context.isInBatch()) {
            executionContext = context.setChecksInProgress();

            checkStatusAll(SetType.Account, false);
            checkStatusAll(SetType.Vault, false);

            // verify if cached context value can be reused
            assert(
                EC.unwrap(executionContext) ==
                    EC.unwrap(context.setChecksInProgress())
            );
        }

        executionContext = context;
    }
}
