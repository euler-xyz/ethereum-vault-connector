// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "../../../src/interfaces/ICreditVaultConnector.sol";

// mock target contract that allows to test call() and impersonate() functions of the CVC
contract Target {
    function callTest(
        address cvc,
        address msgSender,
        uint value,
        bool checksDeferred,
        address onBehalfOfAccount,
        bool operatorAuthenticated,
        bool permitInProgress
    ) external payable {
        (address _onBehalfOfAccount, ) = ICVC(cvc).getExecutionContext(
            address(0)
        );
        uint context = ICVC(cvc).getRawExecutionContext();

        require(msg.sender == msgSender, "ct/invalid-sender");
        require(msg.value == value, "ct/invalid-msg-value");
        require(
            (context & 0xff != 0) == checksDeferred,
            "ct/invalid-checks-deferred"
        );
        require(
            _onBehalfOfAccount == onBehalfOfAccount,
            "ct/invalid-on-behalf-of-account"
        );
        require(
            context & 0x0000ff00000000000000000000000000000000000000000000 == 0,
            "ct/impersonate-lock"
        );
        require(
            (context & 0x00ff0000000000000000000000000000000000000000000000 !=
                0) == operatorAuthenticated,
            "ct/operator-authenticated"
        );
        require(
            (context & 0xff000000000000000000000000000000000000000000000000 !=
                0) == permitInProgress,
            "ct/permit-in-progress"
        );
    }

    function nestedCallTest(
        address cvc,
        address msgSender,
        uint value,
        bool checksDeferred,
        address onBehalfOfAccount,
        bool operatorAuthenticated,
        bool permitInProgress
    ) external payable {
        (address _onBehalfOfAccount, ) = ICVC(cvc).getExecutionContext(
            address(0)
        );
        uint context = ICVC(cvc).getRawExecutionContext();

        require(msg.sender == msgSender, "nct/invalid-sender");
        require(msg.value == value, "nct/invalid-msg-value");
        require(
            (context & 0xff != 0) == checksDeferred,
            "nct/invalid-checks-deferred"
        );
        require(
            _onBehalfOfAccount == onBehalfOfAccount,
            "nct/invalid-on-behalf-of-account"
        );
        require(
            context & 0x0000ff00000000000000000000000000000000000000000000 == 0,
            "nct/impersonate-lock"
        );
        require(
            (context & 0x00ff0000000000000000000000000000000000000000000000 !=
                0) == operatorAuthenticated,
            "nct/operator-authenticated"
        );
        require(
            (context & 0xff000000000000000000000000000000000000000000000000 !=
                0) == permitInProgress,
            "nct/permit-in-progress"
        );

        ICVC(cvc).call(
            address(this),
            address(this),
            abi.encodeWithSelector(
                this.callTest.selector,
                cvc,
                cvc,
                0,
                checksDeferred,
                address(this),
                false,
                false
            )
        );

        (_onBehalfOfAccount, ) = ICVC(cvc).getExecutionContext(address(0));
        context = ICVC(cvc).getRawExecutionContext();
        require(
            _onBehalfOfAccount == onBehalfOfAccount,
            "nct/invalid-on-behalf-of-account-2"
        );
        require(
            context & 0x0000ff00000000000000000000000000000000000000000000 == 0,
            "nct/impersonate-lock"
        );
        require(
            (context & 0x00ff0000000000000000000000000000000000000000000000 !=
                0) == operatorAuthenticated,
            "nct/operator-authenticated"
        );
        require(
            (context & 0xff000000000000000000000000000000000000000000000000 !=
                0) == permitInProgress,
            "nct/permit-in-progress"
        );
    }

    function impersonateTest(
        address cvc,
        address msgSender,
        uint value,
        bool checksDeferred,
        address onBehalfOfAccount
    ) external payable {
        (address _onBehalfOfAccount, ) = ICVC(cvc).getExecutionContext(
            address(0)
        );
        uint context = ICVC(cvc).getRawExecutionContext();

        require(msg.sender == msgSender, "it/invalid-sender");
        require(msg.value == value, "it/invalid-msg-value");
        require(
            (context & 0xff != 0) == checksDeferred,
            "it/invalid-checks-deferred"
        );
        require(
            _onBehalfOfAccount == onBehalfOfAccount,
            "it/invalid-on-behalf-of-account"
        );
        require(
            context & 0xff00000000000000000000000000000000000000000000 != 0,
            "it/impersonate-lock"
        );

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
    }

    function revertEmptyTest() external pure {
        revert();
    }
}
