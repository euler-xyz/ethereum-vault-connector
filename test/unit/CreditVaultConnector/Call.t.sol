// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../cvc/CreditVaultConnectorHarness.sol";

contract CallTest is Test {
    CreditVaultConnectorHarness internal cvc;

    function setUp() public {
        cvc = new CreditVaultConnectorHarness();
    }

    function test_Call(address alice, uint96 seed) public {
        vm.assume(alice != address(0) && alice != address(cvc));

        address account;
        if (seed % 2 == 0) {
            // in this case the account is not alice's sub-account thus alice must be an operator
            account = address(uint160(uint160(alice) ^ 256));
            vm.prank(account);
            cvc.setAccountOperator(account, alice, block.timestamp + 100);
        } else {
            // in this case the account is alice's sub-account
            account = address(uint160(uint160(alice) ^ (seed % 256)));
        }
        vm.assume(account != address(0));

        address targetContract = address(new Target());
        vm.assume(
            targetContract != address(cvc) &&
                !cvc.haveCommonOwner(targetContract, alice)
        );

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
        cvc.call{value: seed}(targetContract, account, data);

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

        items[0].onBehalfOfAccount = alice;
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
        cvc.batch{value: seed}(items);

        // on behalf of account should be correct in a nested call when checks are not deferred
        data = abi.encodeWithSelector(
            Target(targetContract).nestedCallTest.selector,
            address(cvc),
            address(cvc),
            seed,
            false,
            account
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        cvc.call{value: seed}(targetContract, account, data);

        // on behalf of account should also be correct in a nested call when checks are deferred
        items[0].onBehalfOfAccount = account;
        items[0].targetContract = targetContract;
        items[0].value = seed;
        items[0].data = abi.encodeWithSelector(
            Target(targetContract).nestedCallTest.selector,
            address(cvc),
            address(cvc),
            seed,
            true,
            account
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        cvc.batch{value: seed}(items);
    }

    function test_RevertIfNotOwnerOrOperator_Call(
        address alice,
        address bob,
        uint seed
    ) public {
        vm.assume(alice != address(0) && alice != address(cvc));
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
        cvc.call{value: seed}(targetContract, bob, data);
    }

    function test_RevertIfChecksReentrancy_Call(
        address alice,
        uint seed
    ) public {
        vm.assume(alice != address(cvc));

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
        cvc.call{value: seed}(targetContract, alice, data);
    }

    function test_RevertIfImpersonateReentrancy_Call(
        address alice,
        uint seed
    ) public {
        vm.assume(alice != address(cvc));

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
        cvc.call{value: seed}(targetContract, alice, data);
    }

    function test_RevertIfTargetContractInvalid_Call(
        address alice,
        uint seed
    ) public {
        vm.assume(alice != address(0));
        vm.assume(alice != address(cvc));

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
        cvc.call{value: seed}(targetContract, alice, data);

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
        cvc.call{value: seed}(targetContract, alice, data);
    }
}
