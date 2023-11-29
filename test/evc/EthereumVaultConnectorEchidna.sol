// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.19;

import "./EthereumVaultConnectorScribble.sol";

contract EthereumVaultConnectorEchidna is EthereumVaultConnectorScribble {
    using ExecutionContext for EC;
    using Set for SetStorage;

    bool private inPermit;

    function isExecutionContextEqual(EC context) internal view returns (bool result) {
        result = EC.unwrap(executionContext) == EC.unwrap(context);
    }

    modifier onlyOwner(uint152 addressPrefix) override {
        assert(address(this) == msg.sender ? inPermit : true);

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

    modifier onlyOwnerOrOperator(address account) override {
        assert(address(this) == msg.sender ? inPermit : true);

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

    modifier nonReentrantChecks() override {
        EC contextCache = executionContext;

        if (contextCache.areChecksInProgress()) {
            revert EVC_ChecksReentrancy();
        }

        executionContext = contextCache.setChecksInProgress().setOnBehalfOfAccount(address(0));

        _;

        // verify if cached context value can be reused
        assert(isExecutionContextEqual(contextCache.setChecksInProgress().setOnBehalfOfAccount(address(0))));

        executionContext = contextCache;
    }

    function permit(
        address signer,
        uint256 nonceNamespace,
        uint256 nonce,
        uint256 deadline,
        uint256 value,
        bytes calldata data,
        bytes calldata signature
    ) public payable override nonReentrant {
        // copied function body with setting inPermit flag
        inPermit = true;

        super.permit(signer, nonceNamespace, nonce, deadline, value, data, signature);

        inPermit = false;
    }

    function callback(
        address onBehalfOfAccount,
        uint256 value,
        bytes calldata data
    ) public payable override nonReentrant returns (bytes memory result) {
        // copied function body with inserted assertion
        if (address(this) == msg.sender) {
            revert EVC_NotAuthorized();
        }

        EC contextCache = executionContext;
        executionContext = contextCache.increaseCallDepth();

        // call back into the msg.sender with the context set
        bool success;
        (success, result) = callWithContextInternal(msg.sender, onBehalfOfAccount, value, data);

        // verify if cached context value can be reused
        assert(isExecutionContextEqual(contextCache.increaseCallDepth()));

        if (!success) {
            revertBytes(result);
        }

        restoreExecutionContext(contextCache);
    }

    function call(
        address targetContract,
        address onBehalfOfAccount,
        uint256 value,
        bytes calldata data
    ) public payable override nonReentrant returns (bytes memory result) {
        // copied function body with inserted assertion
        if (address(this) == targetContract || address(this) == msg.sender) {
            revert EVC_InvalidAddress();
        }

        EC contextCache = executionContext;
        executionContext = contextCache.increaseCallDepth();

        bool success;
        (success, result) = callInternal(targetContract, onBehalfOfAccount, value, data);

        // verify if cached context value can be reused
        assert(isExecutionContextEqual(contextCache.increaseCallDepth()));

        if (!success) {
            revertBytes(result);
        }

        restoreExecutionContext(contextCache);
    }

    function impersonate(
        address targetCollateral,
        address onBehalfOfAccount,
        uint256 value,
        bytes calldata data
    ) public payable override nonReentrant returns (bytes memory result) {
        if (address(this) == targetCollateral || msg.sender == targetCollateral) {
            revert EVC_InvalidAddress();
        }

        EC contextCache = executionContext;
        executionContext = contextCache.increaseCallDepth().setImpersonationInProgress();

        bool success;
        (success, result) = impersonateInternal(targetCollateral, onBehalfOfAccount, value, data);

        // verify if cached context value can be reused
        assert(isExecutionContextEqual(contextCache.increaseCallDepth().setImpersonationInProgress()));

        if (!success) {
            revertBytes(result);
        }

        restoreExecutionContext(contextCache);
    }

    function batch(BatchItem[] calldata items) public payable override nonReentrant {
        // copied function body with inserted assertion
        EC contextCache = executionContext;
        executionContext = contextCache.increaseCallDepth();

        batchInternal(items);

        // verify if cached context value can be reused
        assert(isExecutionContextEqual(contextCache.increaseCallDepth()));

        restoreExecutionContext(contextCache);
    }

    function callWithContextInternal(
        address targetContract,
        address onBehalfOfAccount,
        uint256 value,
        bytes calldata data
    ) internal override returns (bool success, bytes memory result) {
        // copied function body with inserted assertion
        if (value > 0 && value != type(uint256).max && value > address(this).balance) {
            revert EVC_InvalidValue();
        } else if (value == type(uint256).max) {
            value = address(this).balance;
        }

        EC contextCache = executionContext;

        // EVC can only be msg.sender after the self-call in the permit() function. in that case,
        // the "true" sender address (that is the permit message signer) is taken from the execution context
        address msgSender = address(this) == msg.sender ? contextCache.getOnBehalfOfAccount() : msg.sender;

        emit CallWithContext(msgSender, targetContract, onBehalfOfAccount, bytes4(data));

        // set the onBehalfOfAccount in the execution context for the duration of the call.
        // apart from a usual scenario, clear the operator authenticated flag
        // if about to execute the permit self-call or a callback
        if (
            haveCommonOwnerInternal(onBehalfOfAccount, msgSender) || address(this) == targetContract
                || msg.sender == targetContract
        ) {
            executionContext = contextCache.setOnBehalfOfAccount(onBehalfOfAccount).clearOperatorAuthenticated();
        } else {
            executionContext = contextCache.setOnBehalfOfAccount(onBehalfOfAccount).setOperatorAuthenticated();
        }

        (success, result) = targetContract.call{value: value == type(uint256).max ? address(this).balance : value}(data);

        // verify if cached context value can be reused
        if (
            haveCommonOwnerInternal(onBehalfOfAccount, msgSender) || address(this) == targetContract
                || msg.sender == targetContract
        ) {
            assert(
                isExecutionContextEqual(
                    contextCache.setOnBehalfOfAccount(onBehalfOfAccount).clearOperatorAuthenticated()
                )
            );
        } else {
            assert(
                isExecutionContextEqual(contextCache.setOnBehalfOfAccount(onBehalfOfAccount).setOperatorAuthenticated())
            );
        }

        executionContext = contextCache;
    }

    function restoreExecutionContext(EC contextCache) internal override {
        // copied function body with inserted assertion
        if (!contextCache.areChecksDeferred()) {
            executionContext = contextCache.setChecksInProgress();

            checkStatusAll(SetType.Account);
            checkStatusAll(SetType.Vault);

            // verify if cached context value can be reused
            assert(isExecutionContextEqual(contextCache.setChecksInProgress()));
        }

        executionContext = contextCache;
    }
}
