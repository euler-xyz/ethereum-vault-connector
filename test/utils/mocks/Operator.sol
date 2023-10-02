// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "../../../src/CreditVaultConnector.sol";

// mock operator contract that allows to test operator callback
contract Operator {
    bool public fallbackCalled;
    bytes32 internal expectedHash;
    uint internal expectedValue;
    bool internal expectedSingleOperatorCallAuth;

    function clearFallbackCalled() external {
        fallbackCalled = false;
    }

    function setExpectedHash(bytes calldata data) external {
        expectedHash = keccak256(data);
    }

    function setExpectedValue(uint value) external {
        expectedValue = value;
    }

    function setExpectedSingleOperatorCallAuth(bool single) external {
        expectedSingleOperatorCallAuth = single;
    }

    fallback(bytes calldata data) external payable returns (bytes memory) {
        fallbackCalled = true;

        (address onBahalfOfAccount, ) = ICVC(msg.sender).getExecutionContext(
            address(0)
        );
        (
            uint40 authExpiryTimestamp,
            ,
            bool operatorCallLock,
            bool singleOperatorCallAuth
        ) = ICVC(msg.sender).getAccountOperatorContext(
                onBahalfOfAccount,
                address(this)
            );

        require(operatorCallLock, "o/invalid-lock");
        require(
            singleOperatorCallAuth == expectedSingleOperatorCallAuth,
            "o/invalid-single"
        );
        require(
            (singleOperatorCallAuth &&
                authExpiryTimestamp == block.timestamp) ||
                !singleOperatorCallAuth,
            "o/invalid-timestamp"
        );
        require(data.length > 0, "o/invalid-data");
        require(keccak256(data) == expectedHash, "o/invalid-hash");
        require(msg.value == expectedValue, "o/invalid-value");

        return data;
    }

    receive() external payable {
        revert();
    }
}

contract OperatorMalicious {
    fallback(bytes calldata data) external payable returns (bytes memory) {
        (address account, address operator) = abi.decode(
            data,
            (address, address)
        );

        // try to reenter the CVC contract
        try
            ICVC(msg.sender).installAccountOperator(
                account,
                operator,
                bytes(""),
                0
            )
        {} catch (bytes memory reason) {
            if (
                bytes4(reason) ==
                CreditVaultConnector.CVC_OperatorCallReentrancy.selector
            ) revert();
        }

        return data;
    }
}

contract OperatorMaliciousECDSA {
    fallback(bytes calldata data) external payable returns (bytes memory) {
        (address account, address operator) = abi.decode(
            data,
            (address, address)
        );

        // try to reenter the CVC contract
        try
            ICVC(msg.sender).installAccountOperatorPermitECDSA(
                account,
                operator,
                bytes(""),
                0,
                0,
                0,
                bytes("")
            )
        {
            revert();
        } catch (bytes memory reason) {
            if (
                bytes4(reason) ==
                CreditVaultConnector.CVC_OperatorCallReentrancy.selector
            ) revert();
        }

        return data;
    }
}

contract OperatorMaliciousERC1271 {
    fallback(bytes calldata data) external payable returns (bytes memory) {
        (address account, address operator) = abi.decode(
            data,
            (address, address)
        );

        // try to reenter the CVC contract
        try
            ICVC(msg.sender).installAccountOperatorPermitERC1271(
                account,
                operator,
                bytes(""),
                0,
                0,
                0,
                bytes(""),
                address(0)
            )
        {
            revert();
        } catch (bytes memory reason) {
            if (
                bytes4(reason) ==
                CreditVaultConnector.CVC_OperatorCallReentrancy.selector
            ) revert();
        }

        return data;
    }
}

contract OperatorBatchCallback {
    function callBatch(address cvc, ICVC.BatchItem[] calldata items) external {
        ICVC(cvc).batch(items);
    }
}
