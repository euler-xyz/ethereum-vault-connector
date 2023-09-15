// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "../../src/test/CreditVaultConnectorScribble.sol";

contract CreditVaultConnectorEchidna is CreditVaultConnectorScribble {
    using ExecutionContext for EC;
    using Set for SetStorage;

    modifier nonReentrantChecksEchidna() {
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

    modifier onBehalfOfAccountContextEchidna(address account) {
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

    function impersonateEchidna(
        address targetContract,
        address onBehalfOfAccount,
        bytes calldata data
    ) public payable nonReentrant returns (bool success, bytes memory result) {
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

    function batchEchidna(
        BatchItem[] calldata items
    ) public payable nonReentrant {
        // copied function body with inserted assertion
        EC context = executionContext;

        if (context.isBatchDepthExceeded()) {
            revert CVC_BatchDepthViolation();
        }

        executionContext = context.increaseBathDepth();

        batchInternal(items, false);

        // verify if cached context value can be reused
        assert(
            EC.unwrap(executionContext) ==
                EC.unwrap(context.increaseBathDepth())
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

    function checkAccountStatusEchidna(
        address account
    ) public payable nonReentrantChecksEchidna returns (bool isValid) {
        // copied function body
        (isValid, ) = checkAccountStatusInternal(account);
    }

    function checkAccountsStatusEchidna(
        address[] calldata accounts
    ) public payable nonReentrantChecksEchidna returns (bool[] memory isValid) {
        // copied function body
        isValid = new bool[](accounts.length);

        uint length = accounts.length;
        for (uint i; i < length; ) {
            (isValid[i], ) = checkAccountStatusInternal(accounts[i]);
            unchecked {
                ++i;
            }
        }
    }

    function requireAccountStatusCheckEchidna(
        address account
    ) public payable nonReentrantChecksEchidna {
        // copied function body
        if (executionContext.isInBatch()) {
            accountStatusChecks.insert(account);
        } else {
            requireAccountStatusCheckInternal(account);
        }
    }

    function requireAccountsStatusCheckEchidna(
        address[] calldata accounts
    ) public payable nonReentrantChecksEchidna {
        // copied function body
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

    function requireAccountStatusCheckNowEchidna(
        address account
    ) public payable nonReentrantChecksEchidna {
        // copied function body
        accountStatusChecks.remove(account);
        requireAccountStatusCheckInternal(account);
    }

    function requireAccountsStatusCheckNowEchidna(
        address[] calldata accounts
    ) public payable nonReentrantChecksEchidna {
        // copied function body
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

    function requireAllAccountsStatusCheckNowEchidna()
        public
        payable
        nonReentrantChecksEchidna
    {
        // copied function body
        checkStatusAll(SetType.Account, false);
    }

    function forgiveAccountStatusCheckEchidna(
        address account
    ) public payable nonReentrantChecksEchidna onlyController(account) {
        // copied function body
        accountStatusChecks.remove(account);
    }

    function forgiveAccountsStatusCheckEchidna(
        address[] calldata accounts
    ) public payable nonReentrantChecksEchidna {
        // copied function body
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

    function requireVaultStatusCheckEchidna()
        public
        payable
        nonReentrantChecksEchidna
    {
        // copied function body
        if (executionContext.isInBatch()) {
            vaultStatusChecks.insert(msg.sender);
        } else {
            requireVaultStatusCheckInternal(msg.sender);
        }
    }

    function requireVaultStatusCheckNowEchidna(
        address vault
    ) public payable nonReentrantChecksEchidna {
        // copied function body
        if (vaultStatusChecks.remove(vault)) {
            requireVaultStatusCheckInternal(vault);
        }
    }

    function requireVaultsStatusCheckNowEchidna(
        address[] calldata vaults
    ) public payable nonReentrantChecksEchidna {
        // copied function body
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

    function requireAllVaultsStatusCheckNowEchidna()
        public
        payable
        nonReentrantChecksEchidna
    {
        // copied function body
        checkStatusAll(SetType.Vault, false);
    }

    function forgiveVaultStatusCheckEchidna()
        public
        payable
        nonReentrantChecksEchidna
    {
        // copied function body
        vaultStatusChecks.remove(msg.sender);
    }

    function requireAccountAndVaultStatusCheckEchidna(
        address account
    ) public payable nonReentrantChecksEchidna {
        // copied function body
        if (executionContext.isInBatch()) {
            accountStatusChecks.insert(account);
            vaultStatusChecks.insert(msg.sender);
        } else {
            requireAccountStatusCheckInternal(account);
            requireVaultStatusCheckInternal(msg.sender);
        }
    }

    function callInternal(
        address targetContract,
        address onBehalfOfAccount,
        uint value,
        bytes calldata data
    )
        internal
        override
        onlyOwnerOrOperator(onBehalfOfAccount)
        onBehalfOfAccountContextEchidna(onBehalfOfAccount)
        returns (bool success, bytes memory result)
    {
        // copied function body
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
        override
        onlyController(onBehalfOfAccount)
        onBehalfOfAccountContextEchidna(onBehalfOfAccount)
        returns (bool success, bytes memory result)
    {
        // copied function body
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
}
