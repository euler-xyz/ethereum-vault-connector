// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "./CreditVaultConnectorScribble.sol";

contract CreditVaultConnectorEchidna is CreditVaultConnectorScribble {
    using ExecutionContext for EC;
    using Set for SetStorage;

    bool private inPermit;

    modifier onlyOwner(uint152 addressPrefix) override {
        assert(address(this) == msg.sender ? inPermit : true);

        EC contextCache = executionContext;
        EC contextCopy = contextCache;

        {
            // calculate a phantom address from the address prefix which can be used as an input to internal functions
            address account = address(uint160(addressPrefix) << 8);

            // CVC can only be msg.sender during the self-call in the permit() function. in that case,
            // the "true" sender address (that is the permit message signer) is taken from the execution context
            address msgSender;
            if (address(this) == msg.sender) {
                contextCopy = contextCopy.setPermitInProgress();
                msgSender = contextCopy.getOnBehalfOfAccount();
            } else {
                contextCopy = contextCopy.clearPermitInProgress();
                msgSender = msg.sender;
            }

            assert(msgSender != address(0));

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

        if (!contextCache.isEqual(contextCopy)) {
            executionContext = contextCopy;
        }

        _;

        // verify if cached context value can be reused
        assert(executionContext.isEqual(contextCopy));

        if (!contextCache.isEqual(contextCopy)) {
            executionContext = contextCache;
        }
    }

    modifier onlyOwnerOrOperator(address account) override {
        assert(address(this) == msg.sender ? inPermit : true);

        EC contextCache = executionContext;
        EC contextCopy = contextCache;

        {
            // CVC can only be msg.sender during the self-call in the permit() function. in that case,
            // the "true" sender address (that is the permit message signer) is taken from the execution context
            address msgSender;
            if (address(this) == msg.sender) {
                contextCopy = contextCopy.setPermitInProgress();
                msgSender = contextCopy.getOnBehalfOfAccount();
            } else {
                contextCopy = contextCopy.clearPermitInProgress();
                msgSender = msg.sender;
            }

            assert(msgSender != address(0));

            if (haveCommonOwnerInternal(account, msgSender)) {
                contextCopy = contextCopy.clearOperatorAuthenticated();

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
            } else {
                contextCopy = contextCopy.setOperatorAuthenticated();
                emit OperatorAuthenticated(msgSender, account);
            }
        }

        if (!contextCache.isEqual(contextCopy)) {
            executionContext = contextCopy;
        }

        _;

        // verify if cached context value can be reused
        assert(executionContext.isEqual(contextCopy));

        if (!contextCache.isEqual(contextCopy)) {
            executionContext = contextCache;
        }
    }

    modifier nonReentrantChecks() override {
        EC context = executionContext;

        if (context.areChecksInProgress()) {
            revert CVC_ChecksReentrancy();
        }

        executionContext = context.setChecksInProgress().setOnBehalfOfAccount(
            address(0)
        );

        _;

        // verify if cached context value can be reused
        assert(
            executionContext.isEqual(
                context.setChecksInProgress().setOnBehalfOfAccount(address(0))
            )
        );

        executionContext = context;
    }

    function impersonate(
        address targetContract,
        address onBehalfOfAccount,
        bytes calldata data
    ) public payable override nonReentrant returns (bytes memory result) {
        // copied function body with inserted assertion
        if (targetContract == address(this)) revert CVC_InvalidAddress();

        EC context = executionContext;

        uint value = executionContext.isInBatch() ? 0 : msg.value;

        onBehalfOfAccount = onBehalfOfAccount == address(0)
            ? msg.sender
            : onBehalfOfAccount;

        executionContext = context.setImpersonationInProgress();

        bool success;
        (success, result) = impersonateInternal(
            targetContract,
            onBehalfOfAccount,
            value,
            data
        );

        // verify if cached context value can be reused
        assert(executionContext.isEqual(context.setImpersonationInProgress()));

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

        emit Permit(msg.sender, signer, signature);
        emit NonceUsed(addressPrefix, nonce);

        uint value = executionContext.isInBatch() ? 0 : msg.value;

        // CVC address becomes msg.sender for the duration this self-call
        (bool success, bytes memory result) = callWithContextInternal(
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
        EC contextCache = executionContext;

        if (contextCache.isBatchDepthExceeded()) {
            revert CVC_BatchDepthViolation();
        }

        uint8 batchDepth = contextCache.getBatchDepth() + 1;
        executionContext = contextCache.setBatchDepth(batchDepth);

        emit BatchStart(msg.sender, batchDepth);

        batchInternal(items, false);

        emit BatchEnd(msg.sender, batchDepth);

        // verify if cached context value can be reused
        assert(
            executionContext.isEqual(contextCache.setBatchDepth(batchDepth))
        );

        if (!contextCache.isInBatch()) {
            executionContext = contextCache
                .setChecksInProgress()
                .setOnBehalfOfAccount(address(0));

            checkStatusAll(SetType.Account, false);
            checkStatusAll(SetType.Vault, false);

            // verify if cached context value can be reused
            assert(
                executionContext.isEqual(
                    contextCache.setChecksInProgress().setOnBehalfOfAccount(
                        address(0)
                    )
                )
            );
        }

        executionContext = contextCache;
    }

    function callWithContextInternal(
        address targetContract,
        address onBehalfOfAccount,
        uint value,
        bytes calldata data
    ) internal override returns (bool success, bytes memory result) {
        // copied function body with inserted assertion
        EC contextCache = executionContext;

        executionContext = contextCache.setOnBehalfOfAccount(onBehalfOfAccount);

        (success, result) = targetContract.call{value: value}(data);

        // verify if cached context value can be reused
        assert(
            executionContext.isEqual(
                contextCache.setOnBehalfOfAccount(onBehalfOfAccount)
            )
        );

        executionContext = contextCache;
    }
}
