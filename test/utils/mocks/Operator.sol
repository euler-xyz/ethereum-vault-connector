// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "../../../src/CreditVaultConnector.sol";

// mock operator contract that allows to test operator callback
contract Operator {
    bool public fallbackCalled;
    bytes32 internal expectedHash;
    uint internal expectedValue;

    function clearFallbackCalled() external {
        fallbackCalled = false;
    }

    function setExpectedHash(bytes calldata data) external {
        expectedHash = keccak256(data);
    }

    function setExpectedValue(uint value) external {
        expectedValue = value;
    }

    fallback(bytes calldata data) external payable returns (bytes memory) {
        fallbackCalled = true;

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
    fallback() external payable {
        // try to reenter the CVC contract
        try
            ICVC(msg.sender).installAccountOperator(
                address(0),
                address(0),
                bytes(""),
                0
            )
        {} catch (bytes memory reason) {
            if (
                bytes4(reason) ==
                CreditVaultConnector.CVC_OperatorCallReentrancy.selector
            ) revert();
        }
    }
}

contract OperatorMaliciousECDSA {
    fallback() external payable {
        // try to reenter the CVC contract
        try
            ICVC(msg.sender).installAccountOperatorPermitECDSA(
                address(0),
                address(0),
                bytes(""),
                0,
                0,
                0,
                bytes("")
            )
        {} catch (bytes memory reason) {
            if (
                bytes4(reason) ==
                CreditVaultConnector.CVC_OperatorCallReentrancy.selector
            ) revert();
        }
    }
}

contract OperatorMaliciousERC1271 {
    fallback() external payable {
        // try to reenter the CVC contract
        try
            ICVC(msg.sender).installAccountOperatorPermitERC1271(
                address(0),
                address(0),
                bytes(""),
                0,
                0,
                0,
                bytes(""),
                address(0)
            )
        {} catch (bytes memory reason) {
            if (
                bytes4(reason) ==
                CreditVaultConnector.CVC_OperatorCallReentrancy.selector
            ) revert();
        }
    }
}

contract OperatorBatchCallback {
    function callBatch(address cvc, ICVC.BatchItem[] calldata items) external {
        ICVC(cvc).batch(items);
    }
}
