// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "src/test/CreditVaultConnectorScribble.sol";

contract SetAccountOperatorTest is Test {
    CreditVaultConnector internal cvc;

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
        cvc = new CreditVaultConnectorScribble();
    }

    function test_SetAccountOperator(
        address alice,
        address operator,
        uint40 authExpiry,
        uint40 seed
    ) public {
        vm.assume(alice != address(0));
        vm.assume(!cvc.haveCommonOwner(alice, operator));
        vm.assume(authExpiry >= seed && authExpiry < type(uint40).max - 1);
        vm.assume(seed > 0);

        vm.warp(seed);

        for (uint i = 0; i < 256; ++i) {
            address account = address(uint160(uint160(alice) ^ i));

            (uint40 expiryTimestamp, uint40 magicNumber) = cvc
                .getAccountOperator(account, operator);
            assertEq(expiryTimestamp, 0);
            assertEq(magicNumber, 0);

            if (i == 0) {
                vm.expectRevert(
                    CreditVaultConnector.CVC_AccountOwnerNotRegistered.selector
                );
                cvc.getAccountOwner(account);
            } else {
                assertEq(cvc.getAccountOwner(account), alice);
            }

            // authorize the operator
            vm.prank(alice);
            if (i == 0) {
                vm.expectEmit(true, true, false, false, address(cvc));
                emit AccountsOwnerRegistered(
                    uint152(uint160(alice) >> 8),
                    alice
                );
            }
            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(account, operator, authExpiry);
            vm.recordLogs();
            cvc.setAccountOperator(account, operator, authExpiry);
            Vm.Log[] memory logs = vm.getRecordedLogs();

            assertTrue(i == 0 ? logs.length == 2 : logs.length == 1); // AccountsOwnerRegistered event is emitted only once
            (expiryTimestamp, magicNumber) = cvc.getAccountOperator(
                account,
                operator
            );
            assertEq(expiryTimestamp, authExpiry);
            assertEq(magicNumber, 0);
            assertEq(cvc.getAccountOwner(account), alice);

            // early return if the operator is already enabled with the same expiry timestamp
            vm.prank(alice);
            vm.recordLogs();
            cvc.setAccountOperator(account, operator, authExpiry);
            logs = vm.getRecordedLogs();

            assertEq(logs.length, 0);
            (expiryTimestamp, magicNumber) = cvc.getAccountOperator(
                account,
                operator
            );
            assertEq(expiryTimestamp, authExpiry);
            assertEq(magicNumber, 0);
            assertEq(cvc.getAccountOwner(account), alice);

            // change the authorization expiry timestamp
            vm.prank(alice);
            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(account, operator, authExpiry + 1);
            vm.recordLogs();
            cvc.setAccountOperator(account, operator, authExpiry + 1);
            logs = vm.getRecordedLogs();

            assertEq(logs.length, 1);
            (expiryTimestamp, magicNumber) = cvc.getAccountOperator(
                account,
                operator
            );
            assertEq(expiryTimestamp, authExpiry + 1);
            assertEq(magicNumber, 0);
            assertEq(cvc.getAccountOwner(account), alice);

            // deauthorize the operator
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
            (expiryTimestamp, magicNumber) = cvc.getAccountOperator(
                account,
                operator
            );
            assertEq(expiryTimestamp, block.timestamp - 1);
            assertEq(magicNumber, 0);
            assertEq(cvc.getAccountOwner(account), alice);

            // early return if the operator is already deauthorized with the same timestamp
            vm.prank(alice);
            vm.recordLogs();
            cvc.setAccountOperator(
                account,
                operator,
                uint40(block.timestamp - 1)
            );
            logs = vm.getRecordedLogs();

            assertEq(logs.length, 0);
            (expiryTimestamp, magicNumber) = cvc.getAccountOperator(
                account,
                operator
            );
            assertEq(expiryTimestamp, block.timestamp - 1);
            assertEq(magicNumber, 0);
            assertEq(cvc.getAccountOwner(account), alice);

            // set expiry timestamp to current block if special value is used
            vm.prank(alice);
            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(account, operator, block.timestamp);
            vm.recordLogs();
            cvc.setAccountOperator(account, operator, type(uint40).max);
            logs = vm.getRecordedLogs();

            assertTrue(logs.length == 1);
            (expiryTimestamp, magicNumber) = cvc.getAccountOperator(
                account,
                operator
            );
            assertEq(expiryTimestamp, block.timestamp);
            assertEq(magicNumber, 0);
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

        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperator(account, operator, 0);

        // succeeds if sender is authorized
        account = address(uint160(uint160(alice) ^ 255));
        vm.prank(address(uint160(uint160(alice) ^ 254)));
        cvc.setAccountOperator(account, operator, 0);

        // reverts if sender is not a registered owner
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperator(account, operator, 0);
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
