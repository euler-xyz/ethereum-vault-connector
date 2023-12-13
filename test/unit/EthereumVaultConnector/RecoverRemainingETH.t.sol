// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../../evc/EthereumVaultConnectorHarness.sol";

contract Receiver {
    fallback(bytes calldata data) external payable returns (bytes memory) {
        if (data.length != 0) {
            revert("Receiver: unexpected data");
        }

        revert("Receiver: fallback reverted");

        return data;
    }
}

contract RecoverRemainingETHTest is Test {
    EthereumVaultConnectorHarness internal evc;

    function setUp() public {
        evc = new EthereumVaultConnectorHarness();
    }

    function test_RecoverRemainingETH(address alice, uint64 value, bool isOperatorCalling, uint96 seed) public {
        vm.assume(
            uint160(alice) > 10 && alice != address(evc)
                && !evc.haveCommonOwner(alice, 0x4e59b44847b379578588920cA78FbF26c0B4956C)
                && !evc.haveCommonOwner(alice, 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38)
        );
        vm.assume(seed % 256 != 0);

        address receiver;
        if (isOperatorCalling) {
            // in this case the receiver is not alice thus alice must be an operator
            receiver = address(uint160(alice) ^ 256);
            vm.prank(receiver);
            evc.setAccountOperator(receiver, alice, true);
        } else {
            // in this case the receiver is alice
            receiver = alice;
        }

        vm.deal(address(evc), value);
        vm.prank(alice);
        evc.recoverRemainingETH(receiver);
        assertEq(address(receiver).balance, value);

        // the receiver is not the initially registered owner hence the transaction should revert
        address receiverSubAccount = address(uint160(receiver) ^ (seed % 256));

        if (isOperatorCalling) {
            vm.prank(receiver);
            evc.setAccountOperator(receiverSubAccount, alice, true);
        }

        vm.deal(address(evc), value);
        vm.prank(alice);
        vm.expectRevert(Errors.EVC_InvalidAddress.selector);
        evc.recoverRemainingETH(receiverSubAccount);

        // test that ETH can be recovered from a batch
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].onBehalfOfAccount = address(0);
        items[0].targetContract = address(evc);
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(evc.recoverRemainingETH.selector, receiver);

        vm.deal(address(evc), value);
        vm.prank(alice);
        evc.batch(items);
        assertEq(address(receiver).balance, 2 * uint256(value));

        // the receiver is not the initially registered owner hence the transaction should revert
        items[0].data = abi.encodeWithSelector(evc.recoverRemainingETH.selector, receiverSubAccount);

        vm.deal(address(evc), value);
        vm.prank(alice);
        vm.expectRevert(Errors.EVC_InvalidAddress.selector);
        evc.batch(items);
    }

    function test_RevertIfNotOwnerOrOperator_RecoverRemainingETH(address alice, address bob, uint256 value) public {
        vm.assume(alice != address(0) && alice != address(evc));
        vm.assume(!evc.haveCommonOwner(alice, bob));
        vm.assume(bob != address(0));

        vm.deal(address(evc), value);
        vm.prank(alice);
        vm.expectRevert(Errors.EVC_NotAuthorized.selector);
        evc.recoverRemainingETH(bob);
    }

    function test_RevertIfChecksReentrancy_RecoverRemainingETH(address alice, uint256 value) public {
        vm.assume(alice != address(evc));

        evc.setChecksLock(true);

        vm.deal(address(evc), value);
        vm.prank(alice);
        vm.expectRevert(Errors.EVC_ChecksReentrancy.selector);
        evc.recoverRemainingETH(alice);
    }

    function test_RevertIfImpersonateReentrancy_RecoverRemainingETH(address alice, uint256 value) public {
        vm.assume(alice != address(evc));

        evc.setImpersonateLock(true);

        vm.deal(address(evc), value);
        vm.prank(alice);
        vm.expectRevert(Errors.EVC_ImpersonateReentrancy.selector);
        evc.recoverRemainingETH(alice);
    }

    function test_RevertIfFallbackReverts_RecoverRemainingETH(uint256 value) public {
        address receiver = address(new Receiver());

        vm.assume(receiver != address(evc));

        vm.deal(address(evc), value);
        vm.prank(receiver);
        vm.expectRevert("Receiver: fallback reverted");
        evc.recoverRemainingETH(receiver);
    }
}
