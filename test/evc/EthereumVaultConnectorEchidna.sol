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

    modifier nonReentrantChecks() override {
        // copied modifier body with inserted assertion
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
    ) public payable override nonReentrantChecksAndControlCollateral {
        // copied function body with setting inPermit flag
        inPermit = true;

        super.permit(signer, nonceNamespace, nonce, deadline, value, data, signature);

        inPermit = false;
    }

    function call(
        address targetContract,
        address onBehalfOfAccount,
        uint256 value,
        bytes calldata data
    ) public payable override nonReentrantChecksAndControlCollateral returns (bytes memory result) {
        // copied function body with inserted assertion
        EC contextCache = executionContext;
        executionContext = contextCache.setChecksDeferred();

        bool success;
        (success, result) = callWithAuthenticationInternal(targetContract, onBehalfOfAccount, value, data);

        if (!success) revertBytes(result);

        // verify if cached context value can be reused
        assert(isExecutionContextEqual(contextCache.setChecksDeferred()));

        restoreExecutionContext(contextCache);
    }

    function controlCollateral(
        address targetCollateral,
        address onBehalfOfAccount,
        uint256 value,
        bytes calldata data
    )
        public
        payable
        override
        nonReentrantChecksAndControlCollateral
        onlyController(onBehalfOfAccount)
        returns (bytes memory result)
    {
        // copied function body with inserted assertion
        if (!accountCollaterals[onBehalfOfAccount].contains(targetCollateral)) {
            revert EVC_NotAuthorized();
        }

        EC contextCache = executionContext;
        executionContext = contextCache.setChecksDeferred().setControlCollateralInProgress();

        bool success;
        (success, result) = callWithContextInternal(targetCollateral, onBehalfOfAccount, value, data);

        if (!success) revertBytes(result);

        // verify if cached context value can be reused
        assert(isExecutionContextEqual(contextCache.setChecksDeferred().setControlCollateralInProgress()));

        restoreExecutionContext(contextCache);
    }

    function batch(BatchItem[] calldata items) public payable override nonReentrantChecksAndControlCollateral {
        // copied function body with inserted assertion
        EC contextCache = executionContext;
        executionContext = contextCache.setChecksDeferred();

        uint256 length = items.length;
        for (uint256 i; i < length;) {
            BatchItem calldata item = items[i];
            (bool success, bytes memory result) =
                callWithAuthenticationInternal(item.targetContract, item.onBehalfOfAccount, item.value, item.data);

            if (!success) revertBytes(result);

            unchecked {
                ++i;
            }
        }

        // verify if cached context value can be reused
        assert(isExecutionContextEqual(contextCache.setChecksDeferred()));

        restoreExecutionContext(contextCache);
    }

    function callWithContextInternal(
        address targetContract,
        address onBehalfOfAccount,
        uint256 value,
        bytes calldata data
    ) internal override returns (bool success, bytes memory result) {
        // copied function body with inserted assertion
        if (targetContract == ERC1820_REGISTRY) {
            revert EVC_InvalidAddress();
        }

        if (value == type(uint256).max) {
            value = address(this).balance;
        } else if (value > address(this).balance) {
            revert EVC_InvalidValue();
        }

        EC contextCache = executionContext;

        // EVC can only be msg.sender after the self-call in the permit() function. in that case,
        // the "true" sender address (that is the permit message signer) is taken from the execution context
        address msgSender = address(this) == msg.sender ? contextCache.getOnBehalfOfAccount() : msg.sender;

        // set the onBehalfOfAccount in the execution context for the duration of the external call.
        // considering that the operatorAuthenticated is only meant to be observable by external
        // contracts, it is sufficient to set it here rather than in the authentication functions.
        // apart from the usual scenario (when an owner operates on behalf of its account),
        // the operatorAuthenticated should be cleared when about to execute the permit self-call, a callback,
        // or when the control collateral is in progress (in which case the operatorAuthenticated is not relevant)
        if (
            haveCommonOwnerInternal(onBehalfOfAccount, msgSender) || msg.sender == targetContract
                || address(this) == targetContract || contextCache.isControlCollateralInProgress()
        ) {
            executionContext = contextCache.setOnBehalfOfAccount(onBehalfOfAccount).clearOperatorAuthenticated();
        } else {
            executionContext = contextCache.setOnBehalfOfAccount(onBehalfOfAccount).setOperatorAuthenticated();
        }

        emit CallWithContext(msgSender, targetContract, onBehalfOfAccount, bytes4(data));

        (success, result) = targetContract.call{value: value == type(uint256).max ? address(this).balance : value}(data);

        // verify if cached context value can be reused
        if (
            haveCommonOwnerInternal(onBehalfOfAccount, msgSender) || msg.sender == targetContract
                || address(this) == targetContract || contextCache.isControlCollateralInProgress()
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

    function _msgSender() internal view override returns (address) {
        assert(address(this) == msg.sender ? inPermit : true);
        return super._msgSender();
    }
}
