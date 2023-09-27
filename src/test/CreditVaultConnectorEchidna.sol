// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "../../src/test/CreditVaultConnectorScribble.sol";

contract CreditVaultConnectorEchidna is CreditVaultConnectorScribble {
    using ExecutionContext for EC;
    using Set for SetStorage;

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
