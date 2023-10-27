// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "../../../src/CreditVaultConnector.sol";

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
    ) external payable returns (uint) {
        try ICVC(cvc).getCurrentOnBehalfOfAccount(address(0)) returns (
            address _onBehalfOfAccount,
            bool
        ) {
            require(
                _onBehalfOfAccount == onBehalfOfAccount,
                "ct/invalid-on-behalf-of-account"
            );
        } catch {
            require(
                onBehalfOfAccount == address(0),
                "ct/invalid-on-behalf-of-account-2"
            );
        }
        require(msg.sender == msgSender, "ct/invalid-sender");
        require(msg.value == value, "ct/invalid-msg-value");
        require(
            checksDeferred
                ? ICVC(cvc).getCurrentBatchDepth() > 0
                : ICVC(cvc).getCurrentBatchDepth() == 0,
            "ct/invalid-checks-deferred"
        );

        require(!ICVC(cvc).isImpersonationInProgress(), "ct/impersonate-lock");
        require(
            operatorAuthenticated
                ? ICVC(cvc).isOperatorAuthenticated()
                : !ICVC(cvc).isOperatorAuthenticated(),
            "ct/operator-authenticated"
        );
        require(
            permitInProgress
                ? ICVC(cvc).isPermitInProgress()
                : !ICVC(cvc).isPermitInProgress(),
            "ct/permit-in-progress"
        );

        return msg.value;
    }

    function nestedCallTest(
        address cvc,
        address msgSender,
        uint value,
        bool checksDeferred,
        address onBehalfOfAccount,
        bool operatorAuthenticated,
        bool permitInProgress
    ) external payable returns (uint) {
        try ICVC(cvc).getCurrentOnBehalfOfAccount(address(0)) returns (
            address _onBehalfOfAccount,
            bool
        ) {
            require(
                _onBehalfOfAccount == onBehalfOfAccount,
                "nct/invalid-on-behalf-of-account"
            );
        } catch {
            require(
                onBehalfOfAccount == address(0),
                "nct/invalid-on-behalf-of-account-2"
            );
        }
        require(msg.sender == msgSender, "nct/invalid-sender");
        require(msg.value == value, "nct/invalid-msg-value");
        require(
            checksDeferred
                ? ICVC(cvc).getCurrentBatchDepth() > 0
                : ICVC(cvc).getCurrentBatchDepth() == 0,
            "nct/invalid-checks-deferred"
        );
        require(!ICVC(cvc).isImpersonationInProgress(), "nct/impersonate-lock");
        require(
            operatorAuthenticated
                ? ICVC(cvc).isOperatorAuthenticated()
                : !ICVC(cvc).isOperatorAuthenticated(),
            "nct/operator-authenticated"
        );
        require(
            permitInProgress
                ? ICVC(cvc).isPermitInProgress()
                : !ICVC(cvc).isPermitInProgress(),
            "nct/permit-in-progress"
        );

        bytes memory result = ICVC(cvc).call(
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
        require(abi.decode(result, (uint)) == 0, "nct/result");

        try ICVC(cvc).getCurrentOnBehalfOfAccount(address(0)) returns (
            address _onBehalfOfAccount,
            bool
        ) {
            require(
                _onBehalfOfAccount == onBehalfOfAccount,
                "nct/invalid-on-behalf-of-account-3"
            );
        } catch {
            require(
                onBehalfOfAccount == address(0),
                "nct/invalid-on-behalf-of-account-4"
            );
        }
        require(
            checksDeferred
                ? ICVC(cvc).getCurrentBatchDepth() > 0
                : ICVC(cvc).getCurrentBatchDepth() == 0,
            "nct/invalid-checks-deferred-2"
        );
        require(
            !ICVC(cvc).isImpersonationInProgress(),
            "nct/impersonate-lock-2"
        );
        require(
            operatorAuthenticated
                ? ICVC(cvc).isOperatorAuthenticated()
                : !ICVC(cvc).isOperatorAuthenticated(),
            "nct/operator-authenticated-2"
        );
        require(
            permitInProgress
                ? ICVC(cvc).isPermitInProgress()
                : !ICVC(cvc).isPermitInProgress(),
            "nct/permit-in-progress-2"
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
        try ICVC(cvc).getCurrentOnBehalfOfAccount(address(0)) returns (
            address _onBehalfOfAccount,
            bool
        ) {
            require(
                _onBehalfOfAccount == onBehalfOfAccount,
                "it/invalid-on-behalf-of-account"
            );
        } catch {
            require(
                onBehalfOfAccount == address(0),
                "it/invalid-on-behalf-of-account-2"
            );
        }
        require(msg.sender == msgSender, "it/invalid-sender");
        require(msg.value == value, "it/invalid-msg-value");
        require(
            checksDeferred
                ? ICVC(cvc).getCurrentBatchDepth() > 0
                : ICVC(cvc).getCurrentBatchDepth() == 0,
            "it/invalid-checks-deferred"
        );
        require(ICVC(cvc).isImpersonationInProgress(), "it/impersonate-lock");

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
