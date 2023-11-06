// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../cvc/CreditVaultConnectorHarness.sol";

contract CreditVaultConnectorHandler is CreditVaultConnectorHarness {
    using Set for SetStorage;

    function handlerImpersonate(
        address targetContract,
        address onBehalfOfAccount,
        uint value,
        bytes calldata data
    ) public payable returns (bytes memory result) {
        (bool success, ) = msg.sender.call(
            abi.encodeWithSelector(Vault.clearChecks.selector)
        );
        success;
        clearExpectedChecks();

        result = super.impersonate(
            targetContract,
            onBehalfOfAccount,
            value,
            data
        );

        verifyVaultStatusChecks();
        verifyAccountStatusChecks();
    }
}

contract ImpersonateTest is Test {
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

    function test_Impersonate(address alice, uint96 seed) public {
        vm.assume(alice != address(0) && alice != address(cvc));

        address collateral = address(new Vault(cvc));
        address controller = address(new Vault(cvc));
        vm.assume(collateral != address(cvc));
        vm.assume(!cvc.haveCommonOwner(alice, controller));

        vm.prank(alice);
        cvc.enableCollateral(alice, collateral);

        vm.prank(alice);
        cvc.enableController(alice, controller);

        bytes memory data = abi.encodeWithSelector(
            Target(collateral).impersonateTest.selector,
            address(cvc),
            address(cvc),
            seed,
            alice
        );

        vm.deal(controller, seed);
        vm.expectEmit(true, true, true, true, address(cvc));
        emit CallWithContext(
            controller,
            collateral,
            alice,
            Target.impersonateTest.selector
        );
        vm.prank(controller);
        bytes memory result = cvc.handlerImpersonate{value: seed}(
            collateral,
            alice,
            seed,
            data
        );
        assertEq(abi.decode(result, (uint)), seed);

        cvc.clearExpectedChecks();
        Vault(controller).clearChecks();
    }

    function test_RevertIfDepthExceeded_Impersonate(address alice) external {
        vm.assume(alice != address(cvc));
        address collateral = address(new Vault(cvc));
        address controller = address(new Vault(cvc));

        vm.prank(alice);
        cvc.enableCollateral(alice, collateral);

        vm.prank(alice);
        cvc.enableController(alice, controller);

        cvc.setCallDepth(10);

        vm.prank(controller);
        vm.expectRevert(ExecutionContext.CallDepthViolation.selector);
        cvc.impersonate(collateral, alice, 0, "");
    }

    function test_RevertIfChecksReentrancy_Impersonate(
        address alice,
        uint seed
    ) public {
        vm.assume(alice != address(0) && alice != address(cvc));

        address collateral = address(new Vault(cvc));
        address controller = address(new Vault(cvc));
        vm.assume(collateral != address(cvc));

        vm.prank(alice);
        cvc.enableCollateral(alice, collateral);

        vm.prank(alice);
        cvc.enableController(alice, controller);

        cvc.setChecksLock(true);

        bytes memory data = abi.encodeWithSelector(
            Target(address(cvc)).impersonateTest.selector,
            address(cvc),
            address(cvc),
            seed,
            alice
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(Errors.CVC_ChecksReentrancy.selector);
        cvc.impersonate{value: seed}(collateral, alice, seed, data);
    }

    function test_RevertIfImpersonateReentrancy_Impersonate(
        address alice,
        uint seed
    ) public {
        vm.assume(alice != address(0) && alice != address(cvc));

        address collateral = address(new Vault(cvc));
        address controller = address(new Vault(cvc));
        vm.assume(collateral != address(cvc));

        vm.prank(alice);
        cvc.enableCollateral(alice, collateral);

        vm.prank(alice);
        cvc.enableController(alice, controller);

        cvc.setImpersonateLock(true);

        bytes memory data = abi.encodeWithSelector(
            Target(address(cvc)).impersonateTest.selector,
            address(cvc),
            address(cvc),
            seed,
            alice
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(Errors.CVC_ImpersonateReentrancy.selector);
        cvc.impersonate{value: seed}(collateral, alice, seed, data);
    }

    function test_RevertIfTargetContractInvalid_Impersonate(
        address alice,
        uint seed
    ) public {
        vm.assume(alice != address(0) && alice != address(cvc));

        address controller = address(new Vault(cvc));

        vm.prank(alice);
        cvc.enableController(alice, controller);

        // target contract is the CVC
        bytes memory data = abi.encodeWithSelector(
            Target(address(cvc)).impersonateTest.selector,
            address(cvc),
            address(cvc),
            seed,
            alice
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(Errors.CVC_InvalidAddress.selector);
        cvc.impersonate{value: seed}(address(cvc), alice, seed, data);
    }

    function test_RevertIfNoControllerEnabled_Impersonate(
        address alice,
        uint seed
    ) public {
        vm.assume(alice != address(0) && alice != address(cvc));

        address collateral = address(new Vault(cvc));
        address controller = address(new Vault(cvc));

        vm.assume(collateral != address(cvc));

        vm.prank(alice);
        cvc.enableCollateral(alice, collateral);

        bytes memory data = abi.encodeWithSelector(
            Target(collateral).impersonateTest.selector,
            address(cvc),
            address(cvc),
            seed,
            alice
        );

        vm.deal(controller, seed);
        vm.prank(controller);
        vm.expectRevert(Errors.CVC_ControllerViolation.selector);
        cvc.impersonate{value: seed}(collateral, alice, seed, data);
    }

    function test_RevertIfMultipleControllersEnabled_Impersonate(
        address alice,
        uint seed
    ) public {
        vm.assume(alice != address(0) && alice != address(cvc));

        address collateral = address(new Vault(cvc));
        address controller_1 = address(new Vault(cvc));
        address controller_2 = address(new Vault(cvc));

        vm.assume(collateral != address(cvc));

        // mock checks deferred to enable multiple controllers
        cvc.setCallDepth(1);

        vm.prank(alice);
        cvc.enableCollateral(alice, collateral);

        vm.prank(alice);
        cvc.enableController(alice, controller_1);

        vm.prank(alice);
        cvc.enableController(alice, controller_2);

        bytes memory data = abi.encodeWithSelector(
            Target(collateral).impersonateTest.selector,
            address(cvc),
            address(cvc),
            seed,
            alice
        );

        vm.deal(controller_1, seed);
        vm.prank(controller_1);
        vm.expectRevert(Errors.CVC_ControllerViolation.selector);
        cvc.impersonate{value: seed}(collateral, alice, seed, data);
    }

    function test_RevertIfMsgSenderIsNotEnabledController_Impersonate(
        address alice,
        address randomAddress,
        uint seed
    ) public {
        vm.assume(alice != address(0) && alice != address(cvc));
        vm.assume(uint160(randomAddress) > 10 && randomAddress != address(cvc));

        address collateral = address(new Vault(cvc));
        address controller = address(new Vault(cvc));

        vm.assume(collateral != address(cvc));
        vm.assume(randomAddress != controller);

        vm.prank(alice);
        cvc.enableCollateral(alice, collateral);

        vm.prank(alice);
        cvc.enableController(alice, controller);

        bytes memory data = abi.encodeWithSelector(
            Target(collateral).impersonateTest.selector,
            address(cvc),
            address(cvc),
            seed,
            alice
        );

        vm.deal(randomAddress, seed);
        vm.prank(randomAddress);
        vm.expectRevert(
            abi.encodeWithSelector(Errors.CVC_NotAuthorized.selector)
        );
        cvc.impersonate{value: seed}(collateral, alice, seed, data);
    }

    function test_RevertIfTargetContractIsNotEnabledCollateral_Impersonate(
        address alice,
        address targetContract,
        uint seed
    ) public {
        vm.assume(alice != address(0) && alice != address(cvc));
        vm.assume(targetContract != address(cvc));

        address collateral = address(new Vault(cvc));
        address controller = address(new Vault(cvc));

        vm.assume(targetContract != collateral);

        vm.prank(alice);
        cvc.enableCollateral(alice, collateral);

        vm.prank(alice);
        cvc.enableController(alice, controller);

        bytes memory data = abi.encodeWithSelector(
            Target(collateral).impersonateTest.selector,
            address(cvc),
            address(cvc),
            seed,
            alice
        );

        vm.deal(controller, seed);
        vm.prank(controller);
        vm.expectRevert(
            abi.encodeWithSelector(Errors.CVC_NotAuthorized.selector)
        );
        cvc.impersonate{value: seed}(targetContract, alice, seed, data);
    }

    function test_RevertIfValueExceedsBalance_Impersonate(
        address alice,
        uint128 seed
    ) public {
        vm.assume(alice != address(0) && alice != address(cvc));
        vm.assume(seed > 0);

        address collateral = address(new Vault(cvc));
        address controller = address(new Vault(cvc));
        vm.assume(collateral != address(cvc) && controller != address(cvc));

        vm.prank(alice);
        cvc.enableCollateral(alice, collateral);

        vm.prank(alice);
        cvc.enableController(alice, controller);

        bytes memory data = abi.encodeWithSelector(
            Target(address(cvc)).impersonateTest.selector,
            address(cvc),
            address(cvc),
            seed,
            alice
        );

        // reverts if value exceeds balance
        vm.deal(controller, seed);
        vm.prank(controller);
        vm.expectRevert(Errors.CVC_InvalidValue.selector);
        cvc.impersonate{value: seed - 1}(collateral, alice, seed, data);

        // succeeds if value does not exceed balance
        vm.prank(controller);
        cvc.impersonate{value: seed}(collateral, alice, seed, data);
    }

    function test_RevertIfInternalCallIsUnsuccessful_Impersonate(
        address alice
    ) public {
        // call setUp() explicitly for Dilligence Fuzzing tool to pass
        setUp();

        vm.assume(alice != address(0));
        vm.assume(alice != address(cvc));

        address collateral = address(new Vault(cvc));
        address controller = address(new Vault(cvc));
        vm.assume(collateral != address(cvc) && controller != address(cvc));

        vm.prank(alice);
        cvc.enableCollateral(alice, collateral);

        vm.prank(alice);
        cvc.enableController(alice, controller);

        bytes memory data = abi.encodeWithSelector(
            Target(collateral).revertEmptyTest.selector
        );

        vm.prank(controller);
        vm.expectRevert(Errors.CVC_EmptyError.selector);
        cvc.impersonate(collateral, alice, 0, data);
    }
}
