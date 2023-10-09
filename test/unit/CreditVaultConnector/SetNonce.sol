// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../cvc/CreditVaultConnectorHarness.sol";

contract SetNonceTest is Test {
    CreditVaultConnectorHarness internal cvc;

    event NonceUsed(uint152 indexed addressPrefix, uint indexed nonce);

    function setUp() public {
        cvc = new CreditVaultConnectorHarness();
    }

    function test_SetNonce(
        address alice,
        uint nonceNamespace,
        uint nonce,
        uint8 iterations
    ) public {
        vm.assume(alice != address(0));
        vm.assume(iterations > 0 && iterations < 5);
        vm.assume(nonce > 0 && nonce <= type(uint).max - 256 * iterations);

        for (uint i = 0; i < 256; ++i) {
            address account = address(uint160(uint160(alice) ^ i));

            for (uint j = 0; j < iterations; ++j) {
                assertEq(
                    cvc.getNonce(account, nonceNamespace),
                    i == 0 && j == 0 ? 0 : nonce
                );

                vm.expectEmit(true, true, false, false, address(cvc));
                emit NonceUsed(cvc.getAddressPrefix(account), ++nonce);
                vm.prank(alice);
                cvc.setNonce(account, nonceNamespace, nonce);
                assertEq(cvc.getNonce(account, nonceNamespace), nonce);
            }
        }
    }

    function test_RevertIfNotOwner_SetNonce(
        address alice,
        uint nonceNamespace,
        uint nonce
    ) public {
        vm.assume(alice != address(0));
        vm.assume(alice != address(uint160(uint160(alice) ^ 1)));
        vm.assume(nonce > 0 && nonce < type(uint).max);

        address account = address(uint160(uint160(alice) ^ 256));

        // fails if account does not belong to an owner
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setNonce(account, nonceNamespace, nonce);

        // succeeds if sender is an owner
        account = address(uint160(uint160(alice) ^ 255));
        vm.prank(alice);
        cvc.setNonce(account, nonceNamespace, nonce);

        // fails if owner not consistent
        vm.prank(address(uint160(uint160(alice) ^ 1)));
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setNonce(account, nonceNamespace, nonce);
    }

    function test_RevertIfInvalidNonce_SetNonce(
        address alice,
        uint nonceNamespace,
        uint nonce
    ) public {
        vm.assume(alice != address(0));
        vm.assume(nonce > 0);

        // fails if invalid nonce
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidNonce.selector);
        cvc.setNonce(alice, nonceNamespace, 0);

        // succeeds if valid nonce
        vm.prank(alice);
        cvc.setNonce(alice, nonceNamespace, nonce);

        // fails again if invalid nonce
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidNonce.selector);
        cvc.setNonce(alice, nonceNamespace, nonce);
    }
}
