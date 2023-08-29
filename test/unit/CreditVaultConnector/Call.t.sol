// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "src/test/CreditVaultConnectorHarness.sol";

contract CreditVaultConnectorHandler is CreditVaultConnectorHarness {
    using Set for SetStorage;

    function handlerCall(
        address targetContract,
        address onBehalfOfAccount,
        bytes calldata data
    ) public payable returns (bool success, bytes memory result) {
        (success, result) = super.call(targetContract, onBehalfOfAccount, data);

        verifyStorage();
    }
}

contract CallTest is Test {
    CreditVaultConnectorHandler internal cvc;

    function setUp() public {
        cvc = new CreditVaultConnectorHandler();
    }

    function test_Call(address alice, uint96 seed) public {
        address account;
        if (seed % 2 == 0) {
            // in this case the account is not alice's sub-account thus alice must be an operator
            account = address(uint160(uint160(alice) ^ 256));
            vm.prank(account);
            cvc.setAccountOperator(
                account,
                alice,
                uint40(block.timestamp + 100)
            );
        } else {
            // in this case the account is alice's sub-account
            account = address(uint160(uint160(alice) ^ (seed % 256)));
        }
        vm.assume(account != address(0));

        address targetContract = address(new Target());
        vm.assume(targetContract != address(cvc));

        bytes memory data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector,
            address(cvc),
            address(cvc),
            seed,
            false,
            account
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        (bool success, bytes memory result) = cvc.handlerCall{value: seed}(
            targetContract,
            account,
            data
        );

        assertTrue(success);
        assertEq(abi.decode(result, (uint)), seed);

        // if called from a batch, the ETH value does not get forwarded
        data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector,
            address(cvc),
            address(cvc),
            0, // we're expecting ETH not to get forwarded
            true,
            account
        );

        ICVC.BatchItem[] memory items = new ICVC.BatchItem[](1);

        items[0].onBehalfOfAccount = address(0);
        items[0].targetContract = address(cvc);
        items[0].value = seed; // this value will get ignored
        items[0].data = abi.encodeWithSelector(
            cvc.call.selector,
            targetContract,
            account,
            data
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        cvc.batch(items);

        // should also succeed if the onBehalfOfAccount address passed is 0. it should be replaced with msg.sender
        data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector,
            address(cvc),
            address(cvc),
            seed,
            false,
            alice
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        (success, result) = cvc.handlerCall{value: seed}(
            targetContract,
            address(0),
            data
        );

        assertTrue(success);
        assertEq(abi.decode(result, (uint)), seed);
    }

    function test_RevertIfNotOwnerOrOperator_Call(
        address alice,
        address bob,
        uint seed
    ) public {
        vm.assume(alice != address(0));
        vm.assume(!cvc.haveCommonOwner(alice, bob));
        vm.assume(bob != address(0));

        address targetContract = address(new Target());
        vm.assume(targetContract != address(cvc));

        bytes memory data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector,
            address(cvc),
            address(cvc),
            seed,
            false,
            alice
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        (bool success, ) = cvc.handlerCall{value: seed}(
            targetContract,
            bob,
            data
        );

        assertFalse(success);
    }

    function test_RevertIfChecksReentrancy_Call(
        address alice,
        uint seed
    ) public {
        address targetContract = address(new Target());
        vm.assume(targetContract != address(cvc));

        cvc.setChecksLock(true);

        bytes memory data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector,
            address(cvc),
            targetContract,
            seed,
            false,
            alice
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_ChecksReentrancy.selector);
        (bool success, ) = cvc.handlerCall{value: seed}(
            targetContract,
            alice,
            data
        );

        assertFalse(success);
    }

    function test_RevertIfImpersonateReentrancy_Call(
        address alice,
        uint seed
    ) public {
        address targetContract = address(new Target());
        vm.assume(targetContract != address(cvc));

        cvc.setImpersonateLock(true);

        bytes memory data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector,
            address(cvc),
            targetContract,
            seed,
            false,
            alice
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(
            CreditVaultConnector.CVC_ImpersonateReentrancy.selector
        );
        (bool success, ) = cvc.handlerCall{value: seed}(
            targetContract,
            alice,
            data
        );

        assertFalse(success);
    }

    function test_RevertIfTargetContractInvalid_Call(
        address alice,
        uint seed
    ) public {
        vm.assume(alice != address(0));

        // call setUp() explicitly for Dilligence Fuzzing tool to pass
        setUp();

        // target contract is the CVC
        address targetContract = address(cvc);

        bytes memory data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector,
            address(cvc),
            targetContract,
            seed,
            false,
            alice
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidAddress.selector);

        (bool success, ) = cvc.handlerCall{value: seed}(
            targetContract,
            alice,
            data
        );

        assertFalse(success);

        // target contract is the ERC1820 registry
        targetContract = 0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24;
        address dummyTarget = address(new Target());

        vm.etch(targetContract, dummyTarget.code);

        data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector,
            address(cvc),
            targetContract,
            seed,
            false,
            alice
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidAddress.selector);

        (success, ) = cvc.handlerCall{value: seed}(targetContract, alice, data);

        assertFalse(success);
    }
}
