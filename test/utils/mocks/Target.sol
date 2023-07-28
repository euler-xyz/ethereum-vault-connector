// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "src/interfaces/ICreditVaultProtocol.sol";

// mock target contract that allows to test call() and impersonate() functions of the CVP
contract Target {
    function callTest(
        address cvp,
        address msgSender,
        uint msgValue,
        bool checksDeferred,
        address onBehalfOfAccount
    ) external payable returns (uint) {
        (ICVP.ExecutionContext memory context, ) = ICVP(cvp)
            .getExecutionContext(address(0));

        require(msg.sender == msgSender, "ct/invalid-sender");
        require(msg.value == msgValue, "ct/invalid-msg-value");
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
        address cvp,
        address msgSender,
        uint msgValue,
        bool checksDeferred,
        address onBehalfOfAccount
    ) external payable returns (uint) {
        (ICVP.ExecutionContext memory context, ) = ICVP(cvp)
            .getExecutionContext(address(0));

        require(msg.sender == msgSender, "it/invalid-sender");
        require(msg.value == msgValue, "it/invalid-msg-value");
        require(
            context.batchDepth != 0 == checksDeferred,
            "it/invalid-checks-deferred"
        );
        require(
            context.onBehalfOfAccount == onBehalfOfAccount,
            "it/invalid-on-behalf-of-account"
        );
        require(
            context.impersonateLock == true,
            "it/impersonate-lock"
        );

        // requireAccountStatusCheck and requireAccountsStatusCheck function have their own unit tests
        // therefore it's not necessary to fully verify it here
        if (checksDeferred) {
            require(
                !ICVP(cvp).isAccountStatusCheckDeferred(onBehalfOfAccount),
                "it/1"
            );
            ICVP(cvp).requireAccountStatusCheck(onBehalfOfAccount);
            require(
                ICVP(cvp).isAccountStatusCheckDeferred(onBehalfOfAccount),
                "it/2"
            );
        } else {
            ICVP(cvp).requireAccountStatusCheck(onBehalfOfAccount);
        }

        return msg.value;
    }

    function revertEmptyTest() external pure {
        revert();
    }
}
