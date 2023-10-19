// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../cvc/CreditVaultConnectorHarness.sol";

contract CreditVaultConnectorHandler is CreditVaultConnectorHarness {
    using Set for SetStorage;

    function handlerImpersonate(
        address targetContract,
        address onBehalfOfAccount,
        bytes calldata data
    ) public payable {
        msg.sender.call(abi.encodeWithSelector(Vault.clearChecks.selector));
        clearExpectedChecks();

        super.impersonate(targetContract, onBehalfOfAccount, data);

        verifyVaultStatusChecks();
        verifyAccountStatusChecks();
    }
}

contract ImpersonateTest is Test {
    CreditVaultConnectorHandler internal cvc;

    event Impersonate(
        address indexed controller,
        address indexed collateral,
        address indexed onBehalfOfAccount
    );
    event BatchStart(address indexed caller, uint batchDepth);
    event BatchEnd(address indexed caller, uint batchDepth);

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
            false,
            alice
        );

        vm.deal(controller, seed);
        vm.expectEmit(true, true, true, false, address(cvc));
        emit Impersonate(controller, collateral, alice);
        vm.prank(controller);
        cvc.handlerImpersonate{value: seed}(collateral, alice, data);

        cvc.clearExpectedChecks();
        Vault(controller).clearChecks();

        // if called from a batch, the ETH value does not get forwarded
        data = abi.encodeWithSelector(
            Target(collateral).impersonateTest.selector,
            address(cvc),
            address(cvc),
            0, // we're expecting ETH not to get forwarded
            true,
            alice
        );

        ICVC.BatchItem[] memory items = new ICVC.BatchItem[](1);

        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = address(cvc);
        items[0].value = seed; // this value will get ignored
        items[0].data = abi.encodeWithSelector(
            cvc.impersonate.selector,
            collateral,
            alice,
            data
        );

        vm.deal(controller, seed);
        vm.expectEmit(true, false, false, true, address(cvc));
        emit BatchStart(controller, 1);
        vm.expectEmit(true, true, true, false, address(cvc));
        emit Impersonate(controller, collateral, alice);
        vm.expectEmit(true, false, false, true, address(cvc));
        emit BatchEnd(controller, 1);
        vm.prank(controller);
        cvc.batch(items);
        cvc.verifyVaultStatusChecks();
        cvc.verifyAccountStatusChecks();

        // this call should also succeed if the onBehalfOfAccount address passed is 0.
        // it should be replaced with msg.sender note that in this case the controller
        // tries to act on behalf of itself
        vm.prank(controller);
        cvc.enableCollateral(controller, collateral);

        vm.prank(controller);
        cvc.enableController(controller, controller);

        cvc.clearExpectedChecks();
        Vault(controller).clearChecks();

        data = abi.encodeWithSelector(
            Target(collateral).impersonateTest.selector,
            address(cvc),
            address(cvc),
            seed,
            false,
            alice
        );

        vm.deal(controller, seed);
        vm.expectEmit(true, true, true, false, address(cvc));
        emit Impersonate(controller, collateral, alice);
        vm.prank(controller);
        cvc.handlerImpersonate{value: seed}(collateral, alice, data);
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
            false,
            alice
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_ChecksReentrancy.selector);
        cvc.handlerImpersonate{value: seed}(collateral, alice, data);
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
            false,
            alice
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(
            CreditVaultConnector.CVC_ImpersonateReentrancy.selector
        );
        cvc.handlerImpersonate{value: seed}(collateral, alice, data);
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
            false,
            alice
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidAddress.selector);
        cvc.handlerImpersonate{value: seed}(address(cvc), alice, data);
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
            false,
            alice
        );

        vm.deal(controller, seed);
        vm.prank(controller);
        vm.expectRevert(CreditVaultConnector.CVC_ControllerViolation.selector);
        cvc.handlerImpersonate{value: seed}(collateral, alice, data);
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
        cvc.setBatchDepth(1);

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
            false,
            alice
        );

        vm.deal(controller_1, seed);
        vm.prank(controller_1);
        vm.expectRevert(CreditVaultConnector.CVC_ControllerViolation.selector);
        cvc.handlerImpersonate{value: seed}(collateral, alice, data);
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
            false,
            alice
        );

        vm.deal(randomAddress, seed);
        vm.prank(randomAddress);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_NotAuthorized.selector
            )
        );
        cvc.handlerImpersonate{value: seed}(collateral, alice, data);
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
            false,
            alice
        );

        vm.deal(controller, seed);
        vm.prank(controller);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_NotAuthorized.selector
            )
        );
        cvc.handlerImpersonate{value: seed}(targetContract, alice, data);
    }
}
