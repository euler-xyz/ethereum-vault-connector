// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../cvc/CreditVaultConnectorHarness.sol";

contract PermitsInvalidationTest is Test {
    CreditVaultConnectorHarness internal cvc;

    function setUp() public {
        cvc = new CreditVaultConnectorHarness();
    }

    function test_PermitsInvalidation(
        address alice,
        address operator,
        uint40 seed
    ) public {
        vm.assume(alice != address(0));
        vm.assume(!cvc.haveCommonOwner(alice, operator));
        vm.assume(seed > 0);

        vm.warp(seed);

        for (uint i = 0; i < 256; ++i) {
            address account = address(uint160(uint160(alice) ^ i));

            (
                uint40 lastSignatureTimestampOwner,
                uint40 lastSignatureTimestampAccountOperator
            ) = cvc.getLastSignatureTimestamps(account, operator);
            (, uint40 lastSignatureTimestamp, , ) = cvc
                .getAccountOperatorContext(account, operator);
            assertEq(lastSignatureTimestampOwner, i == 0 ? 0 : block.timestamp);
            assertEq(lastSignatureTimestampAccountOperator, 0);
            assertEq(lastSignatureTimestamp, 0);

            // invalidate permits for operator of the account
            vm.prank(alice);
            cvc.invalidateAccountOperatorPermits(account, operator);

            (
                lastSignatureTimestampOwner,
                lastSignatureTimestampAccountOperator
            ) = cvc.getLastSignatureTimestamps(account, operator);
            (, lastSignatureTimestamp, , ) = cvc.getAccountOperatorContext(
                account,
                operator
            );
            assertEq(lastSignatureTimestampOwner, i == 0 ? 0 : block.timestamp);
            assertEq(lastSignatureTimestampAccountOperator, block.timestamp);
            assertEq(lastSignatureTimestamp, block.timestamp);

            // invalidate all permits for the owner
            vm.prank(alice);
            cvc.invalidateAllPermits();

            (
                lastSignatureTimestampOwner,
                lastSignatureTimestampAccountOperator
            ) = cvc.getLastSignatureTimestamps(account, operator);
            (, lastSignatureTimestamp, , ) = cvc.getAccountOperatorContext(
                account,
                operator
            );
            assertEq(lastSignatureTimestampOwner, block.timestamp);
            assertEq(lastSignatureTimestampAccountOperator, block.timestamp);
            assertEq(lastSignatureTimestamp, block.timestamp);
        }
    }

    function test_RevertIfSenderNotAuthorized_PermitsInvalidation(
        address alice,
        address operator
    ) public {
        vm.assume(alice != address(0));
        vm.assume(!cvc.haveCommonOwner(alice, operator));

        address account = address(uint160(uint160(alice) ^ 256));

        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.invalidateAccountOperatorPermits(account, operator);

        // succeeds if sender is authorized
        account = address(uint160(uint160(alice) ^ 255));
        vm.prank(alice);
        cvc.invalidateAccountOperatorPermits(account, operator);
    }
}
