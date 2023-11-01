// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../cvc/CreditVaultConnectorHarness.sol";

contract CreditVaultConnectorHandler is CreditVaultConnectorHarness {
    using Set for SetStorage;

    function handlerCall(
        address targetContract,
        address onBehalfOfAccount,
        uint value,
        bytes calldata data
    ) public payable returns (bytes memory result) {
        result = super.call(targetContract, onBehalfOfAccount, value, data);

        verifyVaultStatusChecks();
        verifyAccountStatusChecks();
    }
}

contract CallTest is Test {
    CreditVaultConnectorHandler internal cvc;

    event CallWithContext(
        address indexed caller,
        address indexed targetContract,
        address indexed onBehalfOfAccount,
        bytes4 selector
    );

    function setUp() public {
        cvc = new CreditVaultConnectorHandler();
    }

    function test_Call(address alice, uint96 seed) public {
        vm.assume(alice != address(0) && alice != address(cvc));

        address account;
        if (seed % 2 == 0) {
            // in this case the account is not alice's sub-account thus alice must be an operator
            account = address(uint160(alice) ^ 256);
            vm.prank(account);
            cvc.setAccountOperator(account, alice, true);
        } else {
            // in this case the account is alice's sub-account
            account = address(uint160(alice) ^ (seed % 256));
        }
        vm.assume(account != address(0));

        address targetContract = address(new Target());
        vm.assume(
            targetContract != address(cvc) &&
                !cvc.haveCommonOwner(targetContract, alice) &&
                !cvc.haveCommonOwner(targetContract, account)
        );
        address controller = address(new Vault(cvc));

        vm.prank(alice);
        cvc.enableController(account, controller);
        cvc.reset();
        Vault(controller).reset();

        bytes memory data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector,
            address(cvc),
            address(cvc),
            seed,
            account,
            seed % 2 == 0
        );

        vm.deal(alice, seed);
        vm.expectEmit(true, true, true, true, address(cvc));
        emit CallWithContext(
            alice,
            targetContract,
            account,
            Target.callTest.selector
        );
        vm.prank(alice);
        bytes memory result = cvc.handlerCall{value: seed}(
            targetContract,
            account,
            seed,
            data
        );
        assertEq(abi.decode(result, (uint)), seed);

        cvc.reset();
        Vault(controller).reset();

        // on behalf of account should be correct in a nested call as well
        data = abi.encodeWithSelector(
            Target(targetContract).nestedCallTest.selector,
            address(cvc),
            address(cvc),
            seed,
            account,
            seed % 2 == 0
        );

        vm.deal(alice, seed);
        vm.expectEmit(true, true, true, true, address(cvc));
        emit CallWithContext(
            alice,
            targetContract,
            account,
            Target.nestedCallTest.selector
        );
        vm.expectEmit(true, true, true, true, address(cvc));
        emit CallWithContext(
            targetContract,
            targetContract,
            targetContract,
            Target.callTest.selector
        );
        vm.prank(alice);
        result = cvc.handlerCall{value: seed}(
            targetContract,
            account,
            seed,
            data
        );
        assertEq(abi.decode(result, (uint)), seed);
    }

    function test_RevertIfDepthExceeded_Call(address alice) external {
        vm.assume(alice != address(cvc));

        cvc.setCallDepth(10);

        vm.prank(alice);
        vm.expectRevert(ExecutionContext.CallDepthViolation.selector);
        cvc.call(address(0), alice, 0, "");
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
            alice,
            false
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.call{value: seed}(targetContract, bob, seed, data);
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
            address(cvc),
            seed,
            alice,
            false
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_ChecksReentrancy.selector);
        cvc.call{value: seed}(targetContract, alice, seed, data);
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
            address(cvc),
            seed,
            alice,
            false
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(
            CreditVaultConnector.CVC_ImpersonateReentrancy.selector
        );
        cvc.call{value: seed}(targetContract, alice, seed, data);
    }

    function test_RevertIfTargetContractInvalid_Call(
        address alice,
        uint seed
    ) public {
        // call setUp() explicitly for Dilligence Fuzzing tool to pass
        setUp();

        vm.assume(alice != address(0));
        vm.assume(alice != address(cvc));

        // target contract is the CVC
        address targetContract = address(cvc);

        bytes memory data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector,
            address(cvc),
            targetContract,
            seed,
            alice,
            false
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidAddress.selector);
        cvc.call{value: seed}(targetContract, alice, seed, data);

        // target contract is the ERC1820 registry
        targetContract = 0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24;
        address dummyTarget = address(new Target());

        vm.etch(targetContract, dummyTarget.code);

        data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector,
            address(cvc),
            address(cvc),
            seed,
            alice,
            false
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidAddress.selector);
        cvc.call{value: seed}(targetContract, alice, seed, data);
    }

    function test_RevertIfValueExceedsBalance_Call(
        address alice,
        uint128 seed
    ) public {
        vm.assume(alice != address(0) && alice != address(cvc));
        vm.assume(seed > 0);

        address targetContract = address(new Target());
        vm.assume(targetContract != address(cvc));

        bytes memory data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector,
            address(cvc),
            address(cvc),
            seed,
            alice,
            false
        );

        // reverts if value exceeds balance
        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidValue.selector);
        cvc.call{value: seed - 1}(targetContract, alice, seed, data);

        // succeeds if value does not exceed balance
        vm.prank(alice);
        cvc.call{value: seed}(targetContract, alice, seed, data);
    }

    function test_RevertIfInternalCallIsUnsuccessful_Call(
        address alice
    ) public {
        // call setUp() explicitly for Dilligence Fuzzing tool to pass
        setUp();

        vm.assume(alice != address(0));
        vm.assume(alice != address(cvc));

        address targetContract = address(new Target());
        vm.assume(targetContract != address(cvc));

        bytes memory data = abi.encodeWithSelector(
            Target(targetContract).revertEmptyTest.selector
        );

        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_EmptyError.selector);
        cvc.call(targetContract, alice, 0, data);
    }
}
