// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "./CreditVaultConnectorScribble.sol";

contract CreditVaultConnectorEchidna is CreditVaultConnectorScribble {
    using ExecutionContext for EC;
    using Set for SetStorage;

    bool private inPermit;

    modifier onlyOwner(address account) override {
        assert(address(this) == msg.sender ? inPermit : true);

        {
            // CVC can only be msg.sender during the permit() function call. in that case,
            // the caller address (that is permit message signer) is taken from the execution context
            address caller = address(this) == msg.sender
                ? executionContext.getOnBehalfOfAccount()
                : msg.sender;

            assert(caller != address(0));

            if (haveCommonOwnerInternal(account, caller)) {
                address owner = getAccountOwnerInternal(account);

                if (owner == address(0)) {
                    setAccountOwnerInternal(account, caller);
                } else if (owner != caller) {
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
            // CVC can only be msg.sender during the permit() function call. in that case,
            // the caller address (that is permit message signer) is taken from the execution context
            address caller = address(this) == msg.sender
                ? executionContext.getOnBehalfOfAccount()
                : msg.sender;

            assert(caller != address(0));

            if (haveCommonOwnerInternal(account, caller)) {
                address owner = getAccountOwnerInternal(account);

                if (owner == address(0)) {
                    setAccountOwnerInternal(account, caller);
                } else if (owner != caller) {
                    revert CVC_NotAuthorized();
                }
            } else if (operatorLookup[account][caller] < block.timestamp) {
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
    )
        public
        payable
        override
        nonReentrant
        returns (bool success, bytes memory result)
    {
        // copied function body with inserted assertion
        if (targetContract == address(this)) revert CVC_InvalidAddress();

        EC context = executionContext;

        uint value = executionContext.isInBatch() ? 0 : msg.value;

        onBehalfOfAccount = onBehalfOfAccount == address(0)
            ? msg.sender
            : onBehalfOfAccount;

        executionContext = context.setImpersonationInProgress();

        (success, result) = impersonateInternal(
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
    }

    function permit(
        address owner,
        uint nonceNamespace,
        uint deadline,
        bytes calldata data,
        bytes calldata signature
    ) public payable override nonReentrant {
        // copied function body with setting inPermit flag
        inPermit = true;

        if (owner == address(0)) {
            revert CVC_InvalidAddress();
        }

        if (deadline < block.timestamp) {
            revert CVC_InvalidTimestamp();
        }

        if (data.length == 0) {
            revert CVC_InvalidData();
        }

        uint152 addressPrefix = getAddressPrefixInternal(owner);
        uint nextNonce = nonceLookup[addressPrefix][nonceNamespace] + 1;
        bytes32 permitHash = getPermitHash(
            owner,
            nonceNamespace,
            nextNonce,
            deadline,
            data
        );
        address signer = recoverECDSASigner(permitHash, signature);

        nonceLookup[addressPrefix][nonceNamespace] = nextNonce;

        if (
            owner != signer &&
            !isValidERC1271Signature(signer, permitHash, signature)
        ) {
            revert CVC_NotAuthorized();
        }

        uint value = executionContext.isInBatch() ? 0 : msg.value;

        // CVC address becomes msg.sender for the duration this call
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
