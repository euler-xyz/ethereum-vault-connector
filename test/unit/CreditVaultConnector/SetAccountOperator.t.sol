// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../../src/test/CreditVaultConnectorHarness.sol";

contract SetAccountOperatorTest is Test {
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

    function test_WhenOwnerCalling_SetAccountOperator(
        address alice,
        address operator,
        uint40 authExpiry,
        uint40 seed
    ) public {
        vm.assume(alice != address(0));
        vm.assume(!cvc.haveCommonOwner(alice, operator));
        vm.assume(seed > 10 && seed < type(uint40).max - 1000);
        vm.assume(authExpiry >= seed + 10 && authExpiry < type(uint40).max - 1);

        for (uint i = 0; i < 256; ++i) {
            vm.warp(seed);

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
            cvc.setAccountOperator(account, operator, authExpiry);
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
            assertEq(cvc.getAccountOwner(account), alice);

            // early return if the operator is already enabled with the same expiry timestamp
            vm.warp(block.timestamp + 1);
            vm.prank(alice);
            vm.recordLogs();
            cvc.setAccountOperator(account, operator, authExpiry);
            logs = vm.getRecordedLogs();

            assertEq(logs.length, 0);
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
            assertEq(cvc.getAccountOwner(account), alice);

            // change the authorization expiry timestamp
            vm.warp(block.timestamp + 1);
            vm.prank(alice);
            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(account, operator, authExpiry + 1);
            vm.recordLogs();
            cvc.setAccountOperator(account, operator, authExpiry + 1);
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
            assertEq(expiryTimestamp, authExpiry + 1);
            assertEq(lastSignatureTimestamp, block.timestamp);
            assertEq(cvc.getAccountOwner(account), alice);

            // deauthorize the operator
            vm.warp(block.timestamp + 1);
            vm.prank(alice);
            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(
                account,
                operator,
                block.timestamp - 1
            );
            vm.recordLogs();
            cvc.setAccountOperator(
                account,
                operator,
                uint40(block.timestamp - 1)
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
            assertEq(expiryTimestamp, block.timestamp - 1);
            assertEq(lastSignatureTimestamp, block.timestamp);
            assertEq(cvc.getAccountOwner(account), alice);

            // early return if the operator is already deauthorized with the same timestamp
            vm.warp(block.timestamp + 1);
            vm.prank(alice);
            vm.recordLogs();
            cvc.setAccountOperator(
                account,
                operator,
                uint40(block.timestamp - 2)
            );
            logs = vm.getRecordedLogs();

            assertEq(logs.length, 0);
            expiryTimestamp = cvc.getAccountOperatorAuthExpiryTimestamp(
                account,
                operator
            );
            (, lastSignatureTimestamp) = cvc.getLastSignatureTimestamps(
                account,
                operator
            );
            assertEq(expiryTimestamp, block.timestamp - 2);
            assertEq(lastSignatureTimestamp, block.timestamp);
            assertEq(cvc.getAccountOwner(account), alice);

            // set expiry timestamp to current block if special value is used
            vm.warp(block.timestamp + 1);
            vm.prank(alice);
            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(account, operator, block.timestamp);
            vm.recordLogs();
            cvc.setAccountOperator(account, operator, type(uint40).max);
            logs = vm.getRecordedLogs();

            assertTrue(logs.length == 1);
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
            assertEq(cvc.getAccountOwner(account), alice);
        }
    }

    function test_WhenOperatorCalling_SetAccountOperator(
        address alice,
        address operator,
        uint40 authExpiry,
        uint40 seed
    ) public {
        vm.assume(alice != address(0));
        vm.assume(!cvc.haveCommonOwner(alice, operator));
        vm.assume(seed > 10 && seed < type(uint40).max - 1000);
        vm.assume(authExpiry >= seed + 10 && authExpiry < type(uint40).max - 1);

        for (uint i = 0; i < 256; ++i) {
            vm.warp(seed);

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
            cvc.setAccountOperator(account, operator, authExpiry);
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
            assertEq(cvc.getAccountOwner(account), alice);

            // an operator can only deauthorize itself
            vm.warp(block.timestamp + 1);
            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(account, operator, block.timestamp);
            vm.recordLogs();
            vm.prank(operator);
            cvc.setAccountOperator(account, operator, uint40(block.timestamp));
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
            assertEq(cvc.getAccountOwner(account), alice);
        }
    }

    function test_RevertIfSenderNotOwnerAndNotOperator_SetAccountOperator(
        address alice,
        address operator
    ) public {
        vm.assume(alice != address(0) && alice != address(0xfe));
        vm.assume(!cvc.haveCommonOwner(alice, operator));

        address account = address(uint160(uint160(alice) ^ 256));

        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperator(account, operator, 0);

        // succeeds if sender is authorized
        account = address(uint160(uint160(alice) ^ 255));
        vm.prank(address(uint160(uint160(alice) ^ 254)));
        cvc.setAccountOperator(account, operator, 0);

        // reverts if sender is not a registered owner nor operator
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperator(account, operator, 0);

        // reverts if sender is not a registered owner nor operator
        vm.prank(address(uint160(uint160(operator) ^ 1)));
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperator(account, operator, 0);
    }

    function test_RevertWhenOperatorNotAuthorizedToPerformTheOperation_SetAccountOperator(
        address alice,
        address operator,
        uint40 authExpiry,
        uint40 seed
    ) public {
        vm.assume(alice != address(0));
        vm.assume(!cvc.haveCommonOwner(alice, operator));
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
        cvc.setAccountOperator(alice, operator, authExpiry);

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
        cvc.setAccountOperator(alice, operator, uint40(block.timestamp + 1));

        // operator cannot change authorization status for any other operator nor account
        vm.prank(operator);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperator(
            address(uint160(uint160(alice) ^ 1)),
            operator,
            uint40(block.timestamp)
        );

        vm.prank(operator);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperator(
            alice,
            address(uint160(uint160(operator) ^ 1)),
            uint40(block.timestamp)
        );

        // but operator can deauthorize itself
        vm.prank(operator);
        cvc.setAccountOperator(alice, operator, uint40(block.timestamp));

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
    }

    function test_RevertIfOperatorIsSendersAccount_SetAccountOperator(
        address alice,
        uint8 subAccountId
    ) public {
        address operator = address(uint160(uint160(alice) ^ subAccountId));

        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidAddress.selector);
        cvc.setAccountOperator(alice, operator, 0);
    }
}
