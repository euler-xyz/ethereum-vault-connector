// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "src/interfaces/ICreditVaultProtocol.sol";

// mock target contract that allows to test call() and callFromControllerToCollateral() functions of the CVP
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
            context.batchDepth != 1 == checksDeferred,
            "ct/invalid-checks-deferred"
        );
        require(
            context.onBehalfOfAccount == onBehalfOfAccount,
            "ct/invalid-on-behalf-of-account"
        );

        return msg.value;
    }

    function callFromControllerToCollateralTest(
        address cvp,
        address msgSender,
        uint msgValue,
        bool checksDeferred,
        address nextAccountStatusCheckIgnoredFrom,
        address onBehalfOfAccount
    ) external payable returns (uint) {
        (ICVP.ExecutionContext memory context, ) = ICVP(cvp)
            .getExecutionContext(address(0));

        require(msg.sender == msgSender, "cfctct/invalid-sender");
        require(msg.value == msgValue, "cfctct/invalid-msg-value");
        require(
            context.batchDepth != 1 == checksDeferred,
            "cfctct/invalid-checks-deferred"
        );
        require(
            context.onBehalfOfAccount == onBehalfOfAccount,
            "cfctct/invalid-on-behalf-of-account"
        );
        require(
            context.controllerToCollateralCallLock == true,
            "cfctct/controller-to-collateral-call-lock"
        );

        // requireAccountStatusCheck and requireAccountsStatusCheck function have their own unit tests
        // therefore it's not necessary to fully verify it here
        if (checksDeferred) {
            require(
                !ICVP(cvp).isAccountStatusCheckDeferred(onBehalfOfAccount),
                "cfctct/1"
            );
            ICVP(cvp).requireAccountStatusCheck(onBehalfOfAccount);
            require(
                nextAccountStatusCheckIgnoredFrom == address(this) ||
                ICVP(cvp).isAccountStatusCheckDeferred(onBehalfOfAccount),
                "cfctct/2"
            );

            // if ignored, it can be ignored only once
            if (nextAccountStatusCheckIgnoredFrom == address(this)) {
                require(
                    !ICVP(cvp).isAccountStatusCheckDeferred(onBehalfOfAccount),
                    "cfctct/3"
                );
                ICVP(cvp).requireAccountStatusCheck(onBehalfOfAccount);
                require(
                    ICVP(cvp).isAccountStatusCheckDeferred(onBehalfOfAccount),
                    "cfctct/4"
                );
            }
        } else {
            ICVP(cvp).requireAccountStatusCheck(onBehalfOfAccount);
        }

        return msg.value;
    }

    function revertEmptyTest() external pure {
        revert();
    }
}
