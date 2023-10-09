// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../cvc/CreditVaultConnectorHarness.sol";

contract installAccountOperatorTest is Test {
    CreditVaultConnectorHarness internal cvc;

    event OperatorAuthorized(
        address indexed account,
        address indexed operator,
        uint expiryTimestamp
    );
    event OwnerRegistered(uint152 indexed addressPrefix, address indexed owner);

    function setUp() public {
        cvc = new CreditVaultConnectorHarness();
    }

    function test_WhenOwnerCalling_setAccountOperator(
        address alice,
        address operator,
        uint40 authExpiry,
        uint40 seed
    ) public {
        vm.assume(alice != address(0));
        vm.assume(operator != address(0));
        vm.assume(!cvc.haveCommonOwner(alice, operator));
        vm.assume(seed > 10 && seed < type(uint40).max - 1000);
        vm.assume(authExpiry >= seed + 10 && authExpiry < type(uint40).max - 1);

        for (uint i = 0; i < 256; ++i) {
            vm.warp(seed);
            address account = address(uint160(uint160(alice) ^ i));

            assertEq(cvc.getAccountOperator(account, operator), 0);

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
                emit OwnerRegistered(cvc.getAddressPrefix(alice), alice);
            }
            vm.expectEmit(true, true, false, true, address(cvc));
            emit OperatorAuthorized(account, operator, authExpiry);
            vm.recordLogs();
            vm.prank(alice);
            cvc.setAccountOperator(account, operator, authExpiry);

            {
                Vm.Log[] memory logs = vm.getRecordedLogs();
                assertTrue(i == 0 ? logs.length == 2 : logs.length == 1); // OwnerRegistered event is emitted only once
                assertEq(cvc.getAccountOperator(account, operator), authExpiry);
                assertEq(cvc.getAccountOwner(account), alice);
            }

            // don't emit the event if the operator is already enabled with the same expiry timestamp
            vm.warp(block.timestamp + 1);
            vm.prank(alice);
            vm.recordLogs();
            cvc.setAccountOperator(account, operator, authExpiry);

            {
                Vm.Log[] memory logs = vm.getRecordedLogs();
                assertEq(logs.length, 0);
                assertEq(cvc.getAccountOperator(account, operator), authExpiry);
                assertEq(cvc.getAccountOwner(account), alice);
            }

            // change the authorization expiry timestamp
            vm.warp(block.timestamp + 1);
            vm.prank(alice);
            vm.expectEmit(true, true, false, true, address(cvc));
            emit OperatorAuthorized(account, operator, authExpiry + 1);
            vm.recordLogs();
            cvc.setAccountOperator(account, operator, authExpiry + 1);

            {
                Vm.Log[] memory logs = vm.getRecordedLogs();
                assertEq(logs.length, 1);
                assertEq(
                    cvc.getAccountOperator(account, operator),
                    authExpiry + 1
                );
                assertEq(cvc.getAccountOwner(account), alice);
            }

            // deauthorize the operator
            vm.warp(block.timestamp + 1);
            vm.prank(alice);
            vm.expectEmit(true, true, false, true, address(cvc));
            emit OperatorAuthorized(account, operator, block.timestamp - 1);
            vm.recordLogs();
            cvc.setAccountOperator(
                account,
                operator,
                uint40(block.timestamp - 1)
            );

            {
                Vm.Log[] memory logs = vm.getRecordedLogs();
                assertEq(logs.length, 1);
                assertEq(
                    cvc.getAccountOperator(account, operator),
                    block.timestamp - 1
                );
                assertEq(cvc.getAccountOwner(account), alice);
            }

            // don't emit the event if the operator is already deauthorized with the same timestamp
            vm.warp(block.timestamp + 1);
            vm.prank(alice);
            vm.recordLogs();
            cvc.setAccountOperator(
                account,
                operator,
                uint40(block.timestamp - 2)
            );

            {
                Vm.Log[] memory logs = vm.getRecordedLogs();
                assertEq(logs.length, 0);
                assertEq(
                    cvc.getAccountOperator(account, operator),
                    block.timestamp - 2
                );
                assertEq(cvc.getAccountOwner(account), alice);
            }
        }
    }

    function test_WhenOperatorCalling_setAccountOperator(
        address alice,
        address operator,
        uint40 authExpiry,
        uint40 seed
    ) public {
        vm.assume(alice != address(0));
        vm.assume(operator != address(0));
        vm.assume(!cvc.haveCommonOwner(alice, operator));
        vm.assume(seed > 10 && seed < type(uint40).max - 1000);
        vm.assume(authExpiry >= seed + 10 && authExpiry < type(uint40).max - 1);

        for (uint i = 0; i < 256; ++i) {
            vm.warp(seed);
            address account = address(uint160(uint160(alice) ^ i));

            assertEq(cvc.getAccountOperator(account, operator), 0);

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
                emit OwnerRegistered(cvc.getAddressPrefix(alice), alice);
            }
            vm.expectEmit(true, true, false, true, address(cvc));
            emit OperatorAuthorized(account, operator, authExpiry);
            vm.recordLogs();
            vm.prank(alice);
            cvc.setAccountOperator(account, operator, authExpiry);
            Vm.Log[] memory logs = vm.getRecordedLogs();

            assertTrue(i == 0 ? logs.length == 2 : logs.length == 1); // OwnerRegistered event is emitted only once
            assertEq(cvc.getAccountOperator(account, operator), authExpiry);
            assertEq(cvc.getAccountOwner(account), alice);

            // an operator can only deauthorize itself
            vm.expectEmit(true, true, false, true, address(cvc));
            emit OperatorAuthorized(account, operator, block.timestamp);
            vm.recordLogs();
            vm.prank(operator);
            cvc.setAccountOperator(account, operator, uint40(block.timestamp));
            logs = vm.getRecordedLogs();

            assertEq(logs.length, 1);
            assertEq(
                cvc.getAccountOperator(account, operator),
                block.timestamp
            );
            assertEq(cvc.getAccountOwner(account), alice);
        }
    }

    function test_RevertIfSenderNotOwnerAndNotOperator_setAccountOperator(
        address alice,
        address operator
    ) public {
        vm.assume(alice != address(0) && alice != address(0xfe));
        vm.assume(operator != address(0));
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

    function test_RevertWhenOperatorNotAuthorizedToPerformTheOperation_setAccountOperator(
        address alice,
        address operator,
        uint40 authExpiry,
        uint40 seed
    ) public {
        vm.assume(alice != address(0));
        vm.assume(operator != address(0) && address(uint160(operator) ^ 1) != address(0));
        vm.assume(!cvc.haveCommonOwner(alice, operator));
        vm.assume(seed > 10 && seed < type(uint40).max - 1000);
        vm.assume(authExpiry >= seed + 10 && authExpiry < type(uint40).max - 1);

        vm.warp(seed);
        assertEq(cvc.getAccountOperator(alice, operator), 0);

        vm.prank(alice);
        cvc.setAccountOperator(alice, operator, authExpiry);
        assertEq(cvc.getAccountOperator(alice, operator), authExpiry);

        // operator cannot authorize itself (set authorization expiry timestamp in the future)
        vm.prank(operator);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperator(alice, operator, uint40(block.timestamp + 1));

        // operator cannot change authorization status for any other operator nor account
        vm.prank(operator);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperator(
            address(uint160(alice) ^ 1),
            operator,
            uint40(block.timestamp)
        );

        vm.prank(operator);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperator(
            alice,
            address(uint160(operator) ^ 1),
            uint40(block.timestamp)
        );

        // but operator can deauthorize itself
        vm.prank(operator);
        cvc.setAccountOperator(alice, operator, uint40(block.timestamp));

        assertEq(cvc.getAccountOperator(alice, operator), block.timestamp);
    }

    function test_RevertIfOperatorIsInvalidAddress_setAccountOperator(
        address alice,
        uint8 subAccountId
    ) public {
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidAddress.selector);
        cvc.setAccountOperator(alice, address(0), 0);

        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidAddress.selector);
        cvc.setAccountOperator(
            alice,
            address(uint160(uint160(alice) ^ subAccountId)),
            0
        );
    }
}
