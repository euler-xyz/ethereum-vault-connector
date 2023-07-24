// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "src/CreditVaultProtocol.sol";

contract SetAccountOperatorTest is Test {
    CreditVaultProtocol internal cvp;

    event AccountOperatorEnabled(
        address indexed account,
        address indexed operator
    );
    event AccountOperatorDisabled(
        address indexed account,
        address indexed operator
    );
    event AccountsOwnerRegistered(
        uint152 indexed prefix,
        address indexed owner
    );

    function setUp() public {
        cvp = new CreditVaultProtocol();
    }

    function test_SetAccountOperator(address alice, address operator) public {
        vm.assume(alice != address(0));
        vm.assume(!cvp.haveCommonOwner(alice, operator));

        for (uint i = 0; i < 256; ++i) {
            address account = address(uint160(uint160(alice) ^ i));

            assertFalse(cvp.accountOperators(account, operator));

            if (i == 0) {
                vm.expectRevert(
                    CreditVaultProtocol.CVP_AccountOwnerNotRegistered.selector
                );
                cvp.getAccountOwner(account);
            } else {
                assertEq(cvp.getAccountOwner(account), alice);
            }

            vm.prank(alice);
            if (i == 0) {
                vm.expectEmit(true, true, false, false, address(cvp));
                emit AccountsOwnerRegistered(
                    uint152(uint160(alice) >> 8),
                    alice
                );
            }
            vm.expectEmit(true, true, false, false, address(cvp));
            emit AccountOperatorEnabled(account, operator);
            vm.recordLogs();
            cvp.setAccountOperator(account, operator, true);
            Vm.Log[] memory logs = vm.getRecordedLogs();

            assertTrue(i == 0 ? logs.length == 2 : logs.length == 1); // AccountsOwnerRegistered event is emitted only once
            assertTrue(cvp.accountOperators(account, operator));
            assertEq(cvp.getAccountOwner(account), alice);

            // early return if the operator is already enabled
            vm.prank(alice);
            vm.recordLogs();
            cvp.setAccountOperator(account, operator, true);
            logs = vm.getRecordedLogs();

            assertEq(logs.length, 0);
            assertTrue(cvp.accountOperators(account, operator));
            assertEq(cvp.getAccountOwner(account), alice);

            vm.prank(alice);
            vm.expectEmit(true, true, false, false, address(cvp));
            emit AccountOperatorDisabled(account, operator);
            vm.recordLogs();
            cvp.setAccountOperator(account, operator, false);
            logs = vm.getRecordedLogs();

            assertEq(logs.length, 1);
            assertFalse(cvp.accountOperators(account, operator));
            assertEq(cvp.getAccountOwner(account), alice);

            // early return if the operator is already disabled
            vm.prank(alice);
            vm.recordLogs();
            cvp.setAccountOperator(account, operator, false);
            logs = vm.getRecordedLogs();

            assertEq(logs.length, 0);
            assertFalse(cvp.accountOperators(account, operator));
            assertEq(cvp.getAccountOwner(account), alice);
        }
    }

    function test_RevertIfSenderNotAuthorized_SetAccountOperator(
        address alice,
        address operator
    ) public {
        vm.assume(!cvp.haveCommonOwner(alice, operator));

        address account = address(uint160(uint160(alice) ^ 256));

        assertFalse(cvp.accountOperators(account, operator));

        vm.prank(alice);
        vm.expectRevert(CreditVaultProtocol.CVP_NotAuthorized.selector);
        cvp.setAccountOperator(account, operator, true);
    }

    function test_RevertIfOperatorIsSendersAccount_SetAccountOperator(
        address alice,
        uint8 subAccountId
    ) public {
        address operator = address(uint160(uint160(alice) ^ subAccountId));

        assertFalse(cvp.accountOperators(alice, operator));

        vm.prank(alice);
        vm.expectRevert(CreditVaultProtocol.CVP_InvalidAddress.selector);
        cvp.setAccountOperator(alice, operator, true);
    }
}
