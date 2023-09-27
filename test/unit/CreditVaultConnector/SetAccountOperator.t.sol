// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../utils/mocks/Operator.sol";
import "../../../src/test/CreditVaultConnectorHarness.sol";

contract installAccountOperatorTest is Test {
    CreditVaultConnectorHarness internal cvc;

    event AccountOperatorAuthorized(
        address indexed account,
        address indexed operator,
        uint authExpiryTimestamp
    );
    event AccountsOwnerRegistered(
        uint152 indexed prefix,
        address indexed owner
    );

    function setUp() public {
        cvc = new CreditVaultConnectorHarness();
    }

    function test_WhenOwnerCalling_installAccountOperator(
        address alice,
        string memory str,
        uint16 val,
        uint40 authExpiry,
        uint40 seed
    ) public {
        address payable operator = payable(new Operator());
        vm.assume(alice != address(0));
        vm.assume(!cvc.haveCommonOwner(alice, operator));
        vm.assume(
            bytes4(bytes(str)) != 0xc41e79ed &&
                bytes4(bytes(str)) != 0xb79bb2d7 &&
                bytes4(bytes(str)) != 0x1234458c
        );
        vm.assume(seed > 10 && seed < type(uint40).max - 1000);
        vm.assume(authExpiry >= seed + 10 && authExpiry < type(uint40).max - 1);

        vm.deal(alice, type(uint128).max);

        for (uint i = 0; i < 256; ++i) {
            vm.warp(seed);

            bytes memory operatorData = bytes(str);
            uint value = val;
            address account = address(uint160(uint160(alice) ^ i));

            {
                uint40 expiryTimestamp = cvc
                    .getAccountOperatorAuthExpiryTimestamp(account, operator);
                (, uint40 lastSignatureTimestamp) = cvc
                    .getLastSignatureTimestamps(account, operator);
                assertEq(expiryTimestamp, 0);
                assertEq(lastSignatureTimestamp, 0);
            }

            Operator(operator).clearFallbackCalled();
            Operator(operator).setExpectedHash(operatorData);
            Operator(operator).setExpectedValue(value);

            if (i == 0) {
                vm.expectRevert(
                    CreditVaultConnector.CVC_AccountOwnerNotRegistered.selector
                );
                cvc.getAccountOwner(account);
            } else {
                assertEq(cvc.getAccountOwner(account), alice);
            }

            // authorize the operator
            if (i == 0) {
                vm.expectEmit(true, true, false, false, address(cvc));
                emit AccountsOwnerRegistered(cvc.getPrefix(alice), alice);
            }
            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(account, operator, authExpiry);
            vm.recordLogs();
            vm.prank(alice);
            cvc.installAccountOperator{value: value}(
                account,
                operator,
                operatorData,
                authExpiry
            );

            {
                Vm.Log[] memory logs = vm.getRecordedLogs();
                assertTrue(i == 0 ? logs.length == 2 : logs.length == 1); // AccountsOwnerRegistered event is emitted only once
                uint40 expiryTimestamp = cvc
                    .getAccountOperatorAuthExpiryTimestamp(account, operator);
                (, uint40 lastSignatureTimestamp) = cvc
                    .getLastSignatureTimestamps(account, operator);
                assertEq(expiryTimestamp, authExpiry);
                assertEq(lastSignatureTimestamp, block.timestamp);
                assertEq(
                    Operator(operator).fallbackCalled(),
                    operatorData.length > 0 ? true : false
                );
                assertEq(cvc.getAccountOwner(account), alice);
            }

            // don't emit the event if the operator is already enabled with the same expiry timestamp
            operatorData = bytes(abi.encode(str, "1"));
            value++;

            Operator(operator).clearFallbackCalled();
            Operator(operator).setExpectedHash(operatorData);
            Operator(operator).setExpectedValue(value);

            vm.warp(block.timestamp + 1);
            vm.prank(alice);
            vm.recordLogs();
            cvc.installAccountOperator{value: value}(
                account,
                operator,
                operatorData,
                authExpiry
            );

            {
                Vm.Log[] memory logs = vm.getRecordedLogs();
                assertEq(logs.length, 0);
                uint40 expiryTimestamp = cvc
                    .getAccountOperatorAuthExpiryTimestamp(account, operator);
                (, uint40 lastSignatureTimestamp) = cvc
                    .getLastSignatureTimestamps(account, operator);
                assertEq(expiryTimestamp, authExpiry);
                assertEq(lastSignatureTimestamp, block.timestamp);
                assertEq(Operator(operator).fallbackCalled(), true);
                assertEq(cvc.getAccountOwner(account), alice);
            }

            // change the authorization expiry timestamp
            operatorData = bytes(abi.encode(str, "2"));
            value++;

            Operator(operator).clearFallbackCalled();
            Operator(operator).setExpectedHash(operatorData);
            Operator(operator).setExpectedValue(value);

            vm.warp(block.timestamp + 1);
            vm.prank(alice);
            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(account, operator, authExpiry + 1);
            vm.recordLogs();
            cvc.installAccountOperator{value: value}(
                account,
                operator,
                operatorData,
                authExpiry + 1
            );

            {
                Vm.Log[] memory logs = vm.getRecordedLogs();
                assertEq(logs.length, 1);
                uint40 expiryTimestamp = cvc
                    .getAccountOperatorAuthExpiryTimestamp(account, operator);
                (, uint40 lastSignatureTimestamp) = cvc
                    .getLastSignatureTimestamps(account, operator);
                assertEq(expiryTimestamp, authExpiry + 1);
                assertEq(lastSignatureTimestamp, block.timestamp);
                assertEq(Operator(operator).fallbackCalled(), true);
                assertEq(cvc.getAccountOwner(account), alice);
            }

            // deauthorize the operator
            operatorData = bytes(abi.encode(str, "3"));
            value++;

            Operator(operator).clearFallbackCalled();
            Operator(operator).setExpectedHash(operatorData);
            Operator(operator).setExpectedValue(value);

            vm.warp(block.timestamp + 1);
            vm.prank(alice);
            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(
                account,
                operator,
                block.timestamp - 1
            );
            vm.recordLogs();
            cvc.installAccountOperator{value: value}(
                account,
                operator,
                operatorData,
                uint40(block.timestamp - 1)
            );

            {
                Vm.Log[] memory logs = vm.getRecordedLogs();
                assertEq(logs.length, 1);
                uint40 expiryTimestamp = cvc
                    .getAccountOperatorAuthExpiryTimestamp(account, operator);
                (, uint40 lastSignatureTimestamp) = cvc
                    .getLastSignatureTimestamps(account, operator);
                assertEq(expiryTimestamp, block.timestamp - 1);
                assertEq(lastSignatureTimestamp, block.timestamp);
                assertEq(Operator(operator).fallbackCalled(), true);
                assertEq(cvc.getAccountOwner(account), alice);
            }

            // don't emit the event if the operator is already deauthorized with the same timestamp
            operatorData = bytes(abi.encode(str, "4"));
            value++;

            Operator(operator).clearFallbackCalled();
            Operator(operator).setExpectedHash(operatorData);
            Operator(operator).setExpectedValue(value);

            vm.warp(block.timestamp + 1);
            vm.prank(alice);
            vm.recordLogs();
            cvc.installAccountOperator{value: value}(
                account,
                operator,
                operatorData,
                uint40(block.timestamp - 2)
            );

            {
                Vm.Log[] memory logs = vm.getRecordedLogs();
                assertEq(logs.length, 0);
                uint40 expiryTimestamp = cvc
                    .getAccountOperatorAuthExpiryTimestamp(account, operator);
                (, uint40 lastSignatureTimestamp) = cvc
                    .getLastSignatureTimestamps(account, operator);
                assertEq(expiryTimestamp, block.timestamp - 2);
                assertEq(lastSignatureTimestamp, block.timestamp);
                assertEq(Operator(operator).fallbackCalled(), true);
                assertEq(cvc.getAccountOwner(account), alice);
            }

            // don't change the expiry timestamp if the special value is used
            operatorData = bytes(abi.encode(str, "5"));
            value++;

            Operator(operator).clearFallbackCalled();
            Operator(operator).setExpectedHash(operatorData);
            Operator(operator).setExpectedValue(value);

            vm.warp(block.timestamp + 1);
            vm.prank(alice);
            vm.recordLogs();
            cvc.installAccountOperator{value: value}(
                account,
                operator,
                operatorData,
                type(uint40).max
            );

            {
                Vm.Log[] memory logs = vm.getRecordedLogs();
                assertTrue(logs.length == 0);
                uint40 expiryTimestamp = cvc
                    .getAccountOperatorAuthExpiryTimestamp(account, operator);
                (, uint40 lastSignatureTimestamp) = cvc
                    .getLastSignatureTimestamps(account, operator);
                assertEq(expiryTimestamp, block.timestamp - 3);
                assertEq(lastSignatureTimestamp, block.timestamp);
                assertEq(Operator(operator).fallbackCalled(), true);
                assertEq(cvc.getAccountOwner(account), alice);
            }
        }
    }

    function test_WhenOperatorCalling_installAccountOperator(
        address alice,
        string memory str,
        uint16 val,
        uint40 authExpiry,
        uint40 seed
    ) public {
        address payable operator = payable(new Operator());
        vm.assume(alice != address(0));
        vm.assume(!cvc.haveCommonOwner(alice, operator));
        vm.assume(seed > 10 && seed < type(uint40).max - 1000);
        vm.assume(authExpiry >= seed + 10 && authExpiry < type(uint40).max - 1);
        vm.assume(val < type(uint16).max - 10);

        vm.deal(alice, type(uint128).max);
        vm.deal(operator, type(uint128).max);

        for (uint i = 0; i < 256; ++i) {
            vm.warp(seed);

            bytes memory operatorData = bytes(str);
            uint value = val;
            address account = address(uint160(uint160(alice) ^ i));

            uint40 expiryTimestamp = cvc.getAccountOperatorAuthExpiryTimestamp(
                account,
                operator
            );
            (, uint40 lastSignatureTimestamp) = cvc.getLastSignatureTimestamps(
                account,
                operator
            );
            assertEq(expiryTimestamp, 0);
            assertEq(lastSignatureTimestamp, 0);

            Operator(operator).clearFallbackCalled();
            Operator(operator).setExpectedHash(operatorData);
            Operator(operator).setExpectedValue(value);

            if (i == 0) {
                vm.expectRevert(
                    CreditVaultConnector.CVC_AccountOwnerNotRegistered.selector
                );
                cvc.getAccountOwner(account);
            } else {
                assertEq(cvc.getAccountOwner(account), alice);
            }

            // authorize the operator
            if (i == 0) {
                vm.expectEmit(true, true, false, false, address(cvc));
                emit AccountsOwnerRegistered(cvc.getPrefix(alice), alice);
            }
            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(account, operator, authExpiry);
            vm.recordLogs();
            vm.prank(alice);
            cvc.installAccountOperator{value: value}(
                account,
                operator,
                operatorData,
                authExpiry
            );
            Vm.Log[] memory logs = vm.getRecordedLogs();

            assertTrue(i == 0 ? logs.length == 2 : logs.length == 1); // AccountsOwnerRegistered event is emitted only once
            expiryTimestamp = cvc.getAccountOperatorAuthExpiryTimestamp(
                account,
                operator
            );
            (, lastSignatureTimestamp) = cvc.getLastSignatureTimestamps(
                account,
                operator
            );
            assertEq(expiryTimestamp, authExpiry);
            assertEq(lastSignatureTimestamp, block.timestamp);
            assertEq(
                Operator(operator).fallbackCalled(),
                operatorData.length > 0 ? true : false
            );
            assertEq(cvc.getAccountOwner(account), alice);

            // an operator can only deauthorize itself
            operatorData = bytes(abi.encode(str, "1"));
            value++;

            Operator(operator).clearFallbackCalled();
            Operator(operator).setExpectedHash(operatorData);
            Operator(operator).setExpectedValue(value);

            vm.warp(block.timestamp + 1);
            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(account, operator, block.timestamp);
            vm.recordLogs();
            vm.prank(operator);
            cvc.installAccountOperator{value: value}(
                account,
                operator,
                operatorData,
                uint40(block.timestamp)
            );
            logs = vm.getRecordedLogs();

            assertEq(logs.length, 1);
            expiryTimestamp = cvc.getAccountOperatorAuthExpiryTimestamp(
                account,
                operator
            );
            (, lastSignatureTimestamp) = cvc.getLastSignatureTimestamps(
                account,
                operator
            );
            assertEq(expiryTimestamp, block.timestamp);
            assertEq(lastSignatureTimestamp, block.timestamp);
            assertEq(Operator(operator).fallbackCalled(), true);
            assertEq(cvc.getAccountOwner(account), alice);
        }
    }

    function test_BatchCallback_installAccountOperator(
        address alice,
        address collateral
    ) public {
        address operator = address(new OperatorBatchCallback());

        vm.assume(alice != address(0));
        vm.assume(!cvc.haveCommonOwner(alice, operator));

        ICVC.BatchItem[] memory items = new ICVC.BatchItem[](1);
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = address(cvc);
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(
            cvc.enableCollateral.selector,
            alice,
            collateral
        );

        vm.prank(alice);
        cvc.installAccountOperator(
            alice,
            operator,
            abi.encodeWithSelector(
                OperatorBatchCallback.callBatch.selector,
                address(cvc),
                items
            ),
            type(uint40).max
        );

        assertEq(cvc.isCollateralEnabled(alice, collateral), true);
        assertEq(cvc.getAccountOperatorAuthExpiryTimestamp(alice, operator), 0); // special value used thus authExpiryTimestamp doesn't change
    }

    function test_RevertIfOperatorCallReentrancy_installAccountOperator(
        address alice,
        bytes calldata operatorData
    ) public {
        vm.assume(
            bytes4(operatorData) != 0xc41e79ed &&
                bytes4(operatorData) != 0xb79bb2d7 &&
                bytes4(operatorData) != 0x1234458c
        );

        address payable operator = payable(new OperatorMalicious());

        vm.assume(alice != address(0));
        vm.assume(!cvc.haveCommonOwner(alice, operator));
        vm.assume(operatorData.length > 0);

        vm.prank(alice);
        // CVC_OperatorCallFailure is expected due to OperatorMalicious reverting.
        // look at OperatorMalicious implementation for details.
        vm.expectRevert(CreditVaultConnector.CVC_OperatorCallFailure.selector);
        cvc.installAccountOperator(alice, operator, operatorData, 0);

        // succeeds if operator is not called due to empty operatorData
        vm.prank(alice);
        cvc.installAccountOperator(alice, operator, bytes(""), 0);
    }

    function test_RevertIfSenderNotOwnerAndNotOperator_installAccountOperator(
        address alice,
        address operator
    ) public {
        vm.assume(alice != address(0) && alice != address(0xfe));
        vm.assume(!cvc.haveCommonOwner(alice, operator));

        address account = address(uint160(uint160(alice) ^ 256));

        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.installAccountOperator(account, operator, bytes(""), 0);

        // succeeds if sender is authorized
        account = address(uint160(uint160(alice) ^ 255));
        vm.prank(address(uint160(uint160(alice) ^ 254)));
        cvc.installAccountOperator(account, operator, bytes(""), 0);

        // reverts if sender is not a registered owner nor operator
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.installAccountOperator(account, operator, bytes(""), 0);

        // reverts if sender is not a registered owner nor operator
        vm.prank(address(uint160(uint160(operator) ^ 1)));
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.installAccountOperator(account, operator, bytes(""), 0);
    }

    function test_RevertWhenOperatorNotAuthorizedToPerformTheOperation_installAccountOperator(
        address alice,
        bytes calldata operatorData,
        uint40 authExpiry,
        uint40 seed
    ) public {
        address payable operator = payable(new Operator());
        vm.assume(alice != address(0));
        vm.assume(!cvc.haveCommonOwner(alice, operator));
        vm.assume(
            bytes4(operatorData) != 0xc41e79ed &&
                bytes4(operatorData) != 0xb79bb2d7 &&
                bytes4(operatorData) != 0x1234458c
        );
        vm.assume(seed > 10 && seed < type(uint40).max - 1000);
        vm.assume(authExpiry >= seed + 10 && authExpiry < type(uint40).max - 1);

        vm.warp(seed);
        uint40 expiryTimestamp = cvc.getAccountOperatorAuthExpiryTimestamp(
            alice,
            operator
        );
        (, uint40 lastSignatureTimestamp) = cvc.getLastSignatureTimestamps(
            alice,
            operator
        );
        assertEq(expiryTimestamp, 0);
        assertEq(lastSignatureTimestamp, 0);

        vm.prank(alice);
        cvc.installAccountOperator(alice, operator, bytes(""), authExpiry);

        expiryTimestamp = cvc.getAccountOperatorAuthExpiryTimestamp(
            alice,
            operator
        );
        (, lastSignatureTimestamp) = cvc.getLastSignatureTimestamps(
            alice,
            operator
        );
        assertEq(expiryTimestamp, authExpiry);
        assertEq(lastSignatureTimestamp, block.timestamp);

        // operator cannot authorize itself (set authorization expiry timestamp in the future)
        vm.prank(operator);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.installAccountOperator(
            alice,
            operator,
            bytes(""),
            uint40(block.timestamp + 1)
        );

        // operator cannot change authorization status for any other operator nor account
        vm.prank(operator);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.installAccountOperator(
            address(uint160(uint160(alice) ^ 1)),
            operator,
            bytes(""),
            uint40(block.timestamp)
        );

        vm.prank(operator);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.installAccountOperator(
            alice,
            address(uint160(address(operator)) ^ 1),
            bytes(""),
            uint40(block.timestamp)
        );

        // but operator can deauthorize itself and callback itself using operatorData
        Operator(operator).clearFallbackCalled();
        Operator(operator).setExpectedHash(operatorData);

        vm.prank(operator);
        cvc.installAccountOperator(
            alice,
            operator,
            operatorData,
            uint40(block.timestamp)
        );

        expiryTimestamp = cvc.getAccountOperatorAuthExpiryTimestamp(
            alice,
            operator
        );
        (, lastSignatureTimestamp) = cvc.getLastSignatureTimestamps(
            alice,
            operator
        );
        assertEq(expiryTimestamp, block.timestamp);
        assertEq(lastSignatureTimestamp, block.timestamp);
        assertEq(
            Operator(operator).fallbackCalled(),
            operatorData.length > 0 ? true : false
        );
    }

    function test_RevertIfOperatorIsSendersAccount_installAccountOperator(
        address alice,
        uint8 subAccountId
    ) public {
        address operator = address(uint160(uint160(alice) ^ subAccountId));

        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidAddress.selector);
        cvc.installAccountOperator(alice, operator, bytes(""), 0);
    }
}
