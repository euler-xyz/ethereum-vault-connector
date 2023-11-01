// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "../../../src/CreditVaultConnector.sol";

// mock target contract that allows to test call() and impersonate() functions of the CVC
contract Target {
    function callTest(
        address cvc,
        address msgSender,
        uint value,
        address onBehalfOfAccount,
        bool operatorAuthenticated
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
            ICVC(cvc).getCurrentCallDepth() > 0,
            "ct/invalid-checks-deferred"
        );
        require(!ICVC(cvc).areChecksInProgress(), "ct/checks-lock");
        require(!ICVC(cvc).isImpersonationInProgress(), "ct/impersonate-lock");
        require(
            operatorAuthenticated
                ? ICVC(cvc).isOperatorAuthenticated()
                : !ICVC(cvc).isOperatorAuthenticated(),
            "ct/operator-authenticated"
        );

        ICVC(cvc).requireAccountStatusCheck(onBehalfOfAccount);
        require(
            ICVC(cvc).isAccountStatusCheckDeferred(onBehalfOfAccount),
            "ct/account-status-checks-not-deferred"
        );
        return msg.value;
    }

    function nestedCallTest(
        address cvc,
        address msgSender,
        uint value,
        address onBehalfOfAccount,
        bool operatorAuthenticated
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
            ICVC(cvc).getCurrentCallDepth() > 0,
            "nct/invalid-checks-deferred"
        );
        require(!ICVC(cvc).areChecksInProgress(), "nct/checks-lock");
        require(!ICVC(cvc).isImpersonationInProgress(), "nct/impersonate-lock");
        require(
            operatorAuthenticated
                ? ICVC(cvc).isOperatorAuthenticated()
                : !ICVC(cvc).isOperatorAuthenticated(),
            "nct/operator-authenticated"
        );

        bytes memory result = ICVC(cvc).call(
            address(this),
            address(this),
            0,
            abi.encodeWithSelector(
                this.callTest.selector,
                cvc,
                cvc,
                0,
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
            ICVC(cvc).getCurrentCallDepth() > 0,
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

        return msg.value;
    }

    function impersonateTest(
        address cvc,
        address msgSender,
        uint value,
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
            ICVC(cvc).getCurrentCallDepth() > 0,
            "it/invalid-checks-deferred"
        );
        require(!ICVC(cvc).areChecksInProgress(), "it/checks-lock");
        require(ICVC(cvc).isImpersonationInProgress(), "it/impersonate-lock");

        ICVC(cvc).requireAccountStatusCheck(onBehalfOfAccount);
        require(
            ICVC(cvc).isAccountStatusCheckDeferred(onBehalfOfAccount),
            "it/account-status-checks-not-deferred"
        );

        return msg.value;
    }

    function callbackTest(
        address cvc,
        address msgSender,
        uint value,
        address onBehalfOfAccount
    ) external payable returns (uint) {
        try ICVC(cvc).getCurrentOnBehalfOfAccount(address(0)) returns (
            address _onBehalfOfAccount,
            bool
        ) {
            require(
                _onBehalfOfAccount == onBehalfOfAccount,
                "cbt/invalid-on-behalf-of-account"
            );
        } catch {
            require(
                onBehalfOfAccount == address(0),
                "cbt/invalid-on-behalf-of-account-2"
            );
        }
        require(msg.sender == msgSender, "cbt/invalid-sender");
        require(msg.value == value, "ct/invalid-msg-value");
        require(
            ICVC(cvc).getCurrentCallDepth() > 0,
            "cbt/invalid-checks-deferred"
        );

        require(!ICVC(cvc).areChecksInProgress(), "cbt/impersonate-lock");
        require(!ICVC(cvc).isImpersonationInProgress(), "cbt/impersonate-lock");
        require(
            !ICVC(cvc).isOperatorAuthenticated(),
            "cbt/operator-authenticated"
        );

        ICVC(cvc).requireAccountStatusCheck(onBehalfOfAccount);
        require(
            ICVC(cvc).isAccountStatusCheckDeferred(onBehalfOfAccount),
            "cbt/account-status-checks-not-deferred"
        );
        return msg.value;
    }

    function revertEmptyTest() external pure {
        revert();
    }
}
