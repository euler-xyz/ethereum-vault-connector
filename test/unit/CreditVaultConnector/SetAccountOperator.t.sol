// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "src/CreditVaultConnector.sol";

contract SetAccountOperatorTest is Test {
    CreditVaultConnector internal cvc;

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
        cvc = new CreditVaultConnector();
    }

    function test_SetAccountOperator(address alice, address operator) public {
        vm.assume(alice != address(0));
        vm.assume(!cvc.haveCommonOwner(alice, operator));

        for (uint i = 0; i < 256; ++i) {
            address account = address(uint160(uint160(alice) ^ i));

            (bool isAuthorized, uint40 expiryTimestamp) = cvc
                .getAccountOperator(account, operator);
            assertEq(isAuthorized, false);
            assertEq(expiryTimestamp, 0);

            if (i == 0) {
                vm.expectRevert(
                    CreditVaultConnector.CVC_AccountOwnerNotRegistered.selector
                );
                cvc.getAccountOwner(account);
            } else {
                assertEq(cvc.getAccountOwner(account), alice);
            }

            vm.prank(alice);
            if (i == 0) {
                vm.expectEmit(true, true, false, false, address(cvc));
                emit AccountsOwnerRegistered(
                    uint152(uint160(alice) >> 8),
                    alice
                );
            }
            vm.expectEmit(true, true, false, false, address(cvc));
            emit AccountOperatorEnabled(account, operator);
            vm.recordLogs();
            cvc.setAccountOperator(
                account,
                operator,
                true,
                uint40(block.timestamp + 100)
            );
            Vm.Log[] memory logs = vm.getRecordedLogs();

            assertTrue(i == 0 ? logs.length == 2 : logs.length == 1); // AccountsOwnerRegistered event is emitted only once
            (isAuthorized, expiryTimestamp) = cvc.getAccountOperator(
                account,
                operator
            );
            assertEq(isAuthorized, true);
            //assertEq(expiryTimestamp, 0);
            assertEq(cvc.getAccountOwner(account), alice);

            // early return if the operator is already enabled
            vm.prank(alice);
            vm.recordLogs();
            cvc.setAccountOperator(
                account,
                operator,
                true,
                uint40(block.timestamp + 100)
            );
            logs = vm.getRecordedLogs();

            assertEq(logs.length, 0);
            (isAuthorized, expiryTimestamp) = cvc.getAccountOperator(
                account,
                operator
            );
            assertEq(isAuthorized, true);
            //assertEq(expiryTimestamp, 0);
            assertEq(cvc.getAccountOwner(account), alice);

            vm.prank(alice);
            vm.expectEmit(true, true, false, false, address(cvc));
            emit AccountOperatorDisabled(account, operator);
            vm.recordLogs();
            cvc.setAccountOperator(
                account,
                operator,
                false,
                uint40(block.timestamp + 100)
            );
            logs = vm.getRecordedLogs();

            assertEq(logs.length, 1);
            (isAuthorized, expiryTimestamp) = cvc.getAccountOperator(
                account,
                operator
            );
            assertEq(isAuthorized, true);
            //assertEq(expiryTimestamp, 0);
            assertEq(cvc.getAccountOwner(account), alice);

            // early return if the operator is already disabled
            vm.prank(alice);
            vm.recordLogs();
            cvc.setAccountOperator(
                account,
                operator,
                false,
                uint40(block.timestamp + 100)
            );
            logs = vm.getRecordedLogs();

            assertEq(logs.length, 0);
            (isAuthorized, expiryTimestamp) = cvc.getAccountOperator(
                account,
                operator
            );
            assertEq(isAuthorized, true);
            //assertEq(expiryTimestamp, 0);
            assertEq(cvc.getAccountOwner(account), alice);
        }
    }

    function test_RevertIfSenderNotAuthorized_SetAccountOperator(
        address alice,
        address operator
    ) public {
        vm.assume(alice != address(0));
        vm.assume(!cvc.haveCommonOwner(alice, operator));

        address account = address(uint160(uint160(alice) ^ 256));

        (bool isAuthorized, uint40 expiryTimestamp) = cvc.getAccountOperator(
            account,
            operator
        );
        assertEq(isAuthorized, false);
        //assertEq(expiryTimestamp, 0);

        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperator(
            account,
            operator,
            true,
            uint40(block.timestamp + 100)
        );
    }

    function test_RevertIfOperatorIsSendersAccount_SetAccountOperator(
        address alice,
        uint8 subAccountId
    ) public {
        address operator = address(uint160(uint160(alice) ^ subAccountId));

        (bool isAuthorized, uint40 expiryTimestamp) = cvc.getAccountOperator(
            alice,
            operator
        );
        assertEq(isAuthorized, false);
        //assertEq(expiryTimestamp, 0);

        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidAddress.selector);
        cvc.setAccountOperator(
            alice,
            operator,
            true,
            uint40(block.timestamp + 100)
        );
    }
}
