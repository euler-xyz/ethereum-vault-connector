// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../cvc/CreditVaultConnectorHarness.sol";

contract SetNonceTest is Test {
    CreditVaultConnectorHarness internal cvc;

    event NonceUsed(uint152 indexed addressPrefix, uint nonce);

    function setUp() public {
        cvc = new CreditVaultConnectorHarness();
    }

    function test_SetNonce(
        address alice,
        uint nonceNamespace,
        uint nonce,
        uint8 iterations
    ) public {
        vm.assume(alice != address(0) && alice != address(cvc));
        vm.assume(iterations > 0 && iterations < 5);
        vm.assume(nonce > 0 && nonce <= type(uint).max - 256 * iterations);

        uint152 addressPrefix = cvc.getAddressPrefix(alice);
        assertEq(cvc.getNonce(addressPrefix, nonceNamespace), 0);

        vm.expectEmit(true, false, false, true, address(cvc));
        emit NonceUsed(addressPrefix, ++nonce);
        vm.prank(alice);
        cvc.setNonce(addressPrefix, nonceNamespace, nonce);
        assertEq(cvc.getNonce(addressPrefix, nonceNamespace), nonce);
    }

    function test_RevertIfSenderNotOwner_SetNonce(
        address alice,
        address operator,
        uint nonceNamespace,
        uint nonce
    ) public {
        uint152 addressPrefix = cvc.getAddressPrefix(alice);
        vm.assume(alice != address(0) && alice != address(cvc));
        vm.assume(addressPrefix != type(uint152).max);
        vm.assume(operator != address(0));
        vm.assume(!cvc.haveCommonOwner(alice, operator));
        vm.assume(nonce > 0 && nonce < type(uint).max);

        // fails if address prefix does not belong to an owner
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setNonce(addressPrefix + 1, nonceNamespace, nonce);

        // succeeds if address prefix belongs to an owner
        vm.prank(alice);
        cvc.setNonce(addressPrefix, nonceNamespace, nonce);

        // fails if owner not consistent
        vm.prank(address(uint160(uint160(alice) ^ 1)));
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setNonce(addressPrefix, nonceNamespace, nonce);

        // reverts if sender is an operator
        vm.prank(alice);
        cvc.setAccountOperator(alice, operator, true);

        vm.prank(operator);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setNonce(addressPrefix, nonceNamespace, nonce);
    }

    function test_RevertIfInvalidNonce_SetNonce(
        address alice,
        uint nonceNamespace,
        uint nonce
    ) public {
        vm.assume(alice != address(0) && alice != address(cvc));
        vm.assume(nonce > 0);

        uint152 addressPrefix = cvc.getAddressPrefix(alice);

        // fails if invalid nonce
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidNonce.selector);
        cvc.setNonce(addressPrefix, nonceNamespace, 0);

        // succeeds if valid nonce
        vm.prank(alice);
        cvc.setNonce(addressPrefix, nonceNamespace, nonce);

        // fails again if invalid nonce
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidNonce.selector);
        cvc.setNonce(addressPrefix, nonceNamespace, nonce);
    }
}
