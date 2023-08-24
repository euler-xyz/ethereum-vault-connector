// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "src/interfaces/ICreditVaultConnector.sol";

// mock target contract that allows to test call() and impersonate() functions of the CVC
contract Target {
    function callTest(
        address cvc,
        address msgSender,
        uint value,
        bool checksDeferred,
        address onBehalfOfAccount
    ) external payable returns (uint) {
        (ICVC.ExecutionContext memory context, ) = ICVC(cvc)
            .getExecutionContext(address(0));

        require(msg.sender == msgSender, "ct/invalid-sender");
        require(msg.value == value, "ct/invalid-msg-value");
        require(
            context.batchDepth != 0 == checksDeferred,
            "ct/invalid-checks-deferred"
        );
        require(
            context.onBehalfOfAccount == onBehalfOfAccount,
            "ct/invalid-on-behalf-of-account"
        );

        return msg.value;
    }

    function impersonateTest(
        address cvc,
        address msgSender,
        uint value,
        bool checksDeferred,
        address onBehalfOfAccount
    ) external payable returns (uint) {
        (ICVC.ExecutionContext memory context, ) = ICVC(cvc)
            .getExecutionContext(address(0));

        require(msg.sender == msgSender, "it/invalid-sender");
        require(msg.value == value, "it/invalid-msg-value");
        require(
            context.batchDepth != 0 == checksDeferred,
            "it/invalid-checks-deferred"
        );
        require(
            context.onBehalfOfAccount == onBehalfOfAccount,
            "it/invalid-on-behalf-of-account"
        );
        require(context.impersonateLock == true, "it/impersonate-lock");

        // requireAccountStatusCheck and requireAccountsStatusCheck function have their own unit tests
        // therefore it's not necessary to fully verify it here
        if (checksDeferred) {
            require(
                !ICVC(cvc).isAccountStatusCheckDeferred(onBehalfOfAccount),
                "it/1"
            );
            ICVC(cvc).requireAccountStatusCheck(onBehalfOfAccount);
            require(
                ICVC(cvc).isAccountStatusCheckDeferred(onBehalfOfAccount),
                "it/2"
            );
        } else {
            ICVC(cvc).requireAccountStatusCheck(onBehalfOfAccount);
        }

        return msg.value;
    }

    function revertEmptyTest() external pure {
        revert();
    }
}
