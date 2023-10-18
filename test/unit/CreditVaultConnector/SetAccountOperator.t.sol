// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../cvc/CreditVaultConnectorHarness.sol";

contract installAccountOperatorTest is Test {
    CreditVaultConnectorHarness internal cvc;

    event OperatorStatus(
        address indexed account,
        address indexed operator,
        bool indexed authorized
    );
    event OwnerRegistered(uint152 indexed addressPrefix, address indexed owner);

    function setUp() public {
        cvc = new CreditVaultConnectorHarness();
    }

    function test_WhenOwnerCalling_setAccountOperator(
        address alice,
        address operator
    ) public {
        vm.assume(alice != address(0) && alice != address(cvc));
        vm.assume(operator != address(0) && operator != address(cvc));
        vm.assume(!cvc.haveCommonOwner(alice, operator));

        for (uint i = 0; i < 256; ++i) {
            address account = address(uint160(uint160(alice) ^ i));
            assertEq(cvc.isAccountOperatorAuthorized(account, operator), false);

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
            vm.expectEmit(true, true, true, false, address(cvc));
            emit OperatorStatus(account, operator, true);
            vm.recordLogs();
            vm.prank(alice);
            cvc.setAccountOperator(account, operator, true);

            {
                Vm.Log[] memory logs = vm.getRecordedLogs();
                assertTrue(i == 0 ? logs.length == 2 : logs.length == 1); // OwnerRegistered event is emitted only once
                assertEq(
                    cvc.isAccountOperatorAuthorized(account, operator),
                    true
                );
                assertEq(cvc.getAccountOwner(account), alice);
            }

            // don't emit the event if the operator is already authorized
            vm.recordLogs();
            vm.prank(alice);
            cvc.setAccountOperator(account, operator, true);

            {
                Vm.Log[] memory logs = vm.getRecordedLogs();
                assertEq(logs.length, 0);
                assertEq(
                    cvc.isAccountOperatorAuthorized(account, operator),
                    true
                );
                assertEq(cvc.getAccountOwner(account), alice);
            }

            // deauthorize the operator
            vm.expectEmit(true, true, true, false, address(cvc));
            emit OperatorStatus(account, operator, false);
            vm.recordLogs();
            vm.prank(alice);
            cvc.setAccountOperator(account, operator, false);

            {
                Vm.Log[] memory logs = vm.getRecordedLogs();
                assertEq(logs.length, 1);
                assertEq(
                    cvc.isAccountOperatorAuthorized(account, operator),
                    false
                );
                assertEq(cvc.getAccountOwner(account), alice);
            }

            // don't emit the event if the operator is already deauthorized
            vm.recordLogs();
            vm.prank(alice);
            cvc.setAccountOperator(account, operator, false);

            {
                Vm.Log[] memory logs = vm.getRecordedLogs();
                assertEq(logs.length, 0);
                assertEq(
                    cvc.isAccountOperatorAuthorized(account, operator),
                    false
                );
                assertEq(cvc.getAccountOwner(account), alice);
            }
        }
    }

    function test_WhenOperatorCalling_setAccountOperator(
        address alice,
        address operator
    ) public {
        vm.assume(alice != address(0) && alice != address(cvc));
        vm.assume(operator != address(0) && operator != address(cvc));
        vm.assume(!cvc.haveCommonOwner(alice, operator));

        for (uint i = 0; i < 256; ++i) {
            address account = address(uint160(uint160(alice) ^ i));
            assertEq(cvc.isAccountOperatorAuthorized(account, operator), false);

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
            vm.expectEmit(true, true, true, false, address(cvc));
            emit OperatorStatus(account, operator, true);
            vm.recordLogs();
            vm.prank(alice);
            cvc.setAccountOperator(account, operator, true);
            Vm.Log[] memory logs = vm.getRecordedLogs();

            assertTrue(i == 0 ? logs.length == 2 : logs.length == 1); // OwnerRegistered event is emitted only once
            assertEq(cvc.isAccountOperatorAuthorized(account, operator), true);
            assertEq(cvc.getAccountOwner(account), alice);

            // an operator can only deauthorize itself
            vm.expectEmit(true, true, true, false, address(cvc));
            emit OperatorStatus(account, operator, false);
            vm.recordLogs();
            vm.prank(operator);
            cvc.setAccountOperator(account, operator, false);
            logs = vm.getRecordedLogs();

            assertEq(logs.length, 1);
            assertEq(cvc.isAccountOperatorAuthorized(account, operator), false);
            assertEq(cvc.getAccountOwner(account), alice);
        }
    }

    function test_RevertIfSenderNotOwnerAndNotOperator_setAccountOperator(
        address alice,
        address operator
    ) public {
        vm.assume(
            alice != address(0) &&
                alice != address(0xfe) &&
                alice != address(cvc)
        );
        vm.assume(operator != address(0));
        vm.assume(!cvc.haveCommonOwner(alice, operator));

        address account = address(uint160(uint160(alice) ^ 256));

        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperator(account, operator, true);

        // succeeds if sender is authorized
        account = address(uint160(uint160(alice) ^ 255));
        vm.prank(address(uint160(uint160(alice) ^ 254)));
        cvc.setAccountOperator(account, operator, true);

        // reverts if sender is not a registered owner nor operator
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperator(account, operator, true);

        // reverts if sender is not a registered owner nor operator
        vm.prank(address(uint160(uint160(operator) ^ 1)));
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperator(account, operator, true);
    }

    function test_RevertWhenOperatorNotAuthorizedToPerformTheOperation_setAccountOperator(
        address alice,
        address operator
    ) public {
        vm.assume(alice != address(0) && alice != address(cvc));
        vm.assume(
            operator != address(0) &&
                address(uint160(operator) ^ 1) != address(0) &&
                operator != address(cvc)
        );
        vm.assume(!cvc.haveCommonOwner(alice, operator));

        assertEq(cvc.isAccountOperatorAuthorized(alice, operator), false);

        vm.prank(alice);
        cvc.setAccountOperator(alice, operator, true);
        assertEq(cvc.isAccountOperatorAuthorized(alice, operator), true);

        // operator can re-authorize itself as it has no effect (but there will be no revert)
        vm.prank(operator);
        cvc.setAccountOperator(alice, operator, true);

        // operator cannot change authorization status for any other operator nor account
        vm.prank(operator);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperator(address(uint160(alice) ^ 1), operator, true);

        vm.prank(operator);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperator(alice, address(uint160(operator) ^ 1), true);

        vm.prank(alice);
        cvc.setAccountOperator(alice, address(uint160(operator) ^ 1), true);

        vm.prank(operator);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperator(alice, address(uint160(operator) ^ 1), false);

        // operator can deauthorize itself
        vm.prank(operator);
        cvc.setAccountOperator(alice, operator, false);

        assertEq(cvc.isAccountOperatorAuthorized(alice, operator), false);
    }

    function test_RevertIfOperatorIsInvalidAddress_setAccountOperator(
        address alice,
        uint8 subAccountId
    ) public {
        vm.assume(alice != address(cvc));

        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidAddress.selector);
        cvc.setAccountOperator(alice, address(0), true);

        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidAddress.selector);
        cvc.setAccountOperator(
            alice,
            address(uint160(uint160(alice) ^ subAccountId)),
            true
        );
    }
}
