// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../../evc/EthereumVaultConnectorHarness.sol";

contract EthereumVaultConnectorHandler is EthereumVaultConnectorHarness {
    using Set for SetStorage;

    function handlerImpersonate(
        address targetContract,
        address onBehalfOfAccount,
        uint256 value,
        bytes calldata data
    ) public payable returns (bytes memory result) {
        (bool success,) = msg.sender.call(abi.encodeWithSelector(Vault.clearChecks.selector));
        success;
        clearExpectedChecks();

        result = super.impersonate(targetContract, onBehalfOfAccount, value, data);

        verifyVaultStatusChecks();
        verifyAccountStatusChecks();
    }
}

contract ImpersonateTest is Test {
    EthereumVaultConnectorHandler internal evc;

    event CallWithContext(
        address indexed caller, address indexed targetContract, address indexed onBehalfOfAccount, bytes4 selector
    );

    function setUp() public {
        evc = new EthereumVaultConnectorHandler();
    }

    function test_Impersonate(address alice, uint96 seed) public {
        vm.assume(alice != address(0) && alice != address(evc));

        address collateral = address(new Vault(evc));
        address controller = address(new Vault(evc));
        vm.assume(collateral != address(evc));
        vm.assume(!evc.haveCommonOwner(alice, controller));

        vm.prank(alice);
        evc.enableCollateral(alice, collateral);

        vm.prank(alice);
        evc.enableController(alice, controller);

        bytes memory data =
            abi.encodeWithSelector(Target(collateral).impersonateTest.selector, address(evc), address(evc), seed, alice);

        vm.deal(controller, seed);
        vm.expectEmit(true, true, true, true, address(evc));
        emit CallWithContext(controller, collateral, alice, Target.impersonateTest.selector);
        vm.prank(controller);
        bytes memory result = evc.handlerImpersonate{value: seed}(collateral, alice, seed, data);
        assertEq(abi.decode(result, (uint256)), seed);

        evc.clearExpectedChecks();
        Vault(controller).clearChecks();
    }

    function test_RevertIfDepthExceeded_Impersonate(address alice) external {
        vm.assume(alice != address(evc));
        address collateral = address(new Vault(evc));
        address controller = address(new Vault(evc));

        vm.prank(alice);
        evc.enableCollateral(alice, collateral);

        vm.prank(alice);
        evc.enableController(alice, controller);

        evc.setCallDepth(10);

        vm.prank(controller);
        vm.expectRevert(ExecutionContext.CallDepthViolation.selector);
        evc.impersonate(collateral, alice, 0, "");
    }

    function test_RevertIfChecksReentrancy_Impersonate(address alice, uint256 seed) public {
        vm.assume(alice != address(0) && alice != address(evc));

        address collateral = address(new Vault(evc));
        address controller = address(new Vault(evc));
        vm.assume(collateral != address(evc));

        vm.prank(alice);
        evc.enableCollateral(alice, collateral);

        vm.prank(alice);
        evc.enableController(alice, controller);

        evc.setChecksLock(true);

        bytes memory data = abi.encodeWithSelector(
            Target(address(evc)).impersonateTest.selector, address(evc), address(evc), seed, alice
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(Errors.EVC_ChecksReentrancy.selector);
        evc.impersonate{value: seed}(collateral, alice, seed, data);
    }

    function test_RevertIfImpersonateReentrancy_Impersonate(address alice, uint256 seed) public {
        vm.assume(alice != address(0) && alice != address(evc));

        address collateral = address(new Vault(evc));
        address controller = address(new Vault(evc));
        vm.assume(collateral != address(evc));

        vm.prank(alice);
        evc.enableCollateral(alice, collateral);

        vm.prank(alice);
        evc.enableController(alice, controller);

        evc.setImpersonateLock(true);

        bytes memory data = abi.encodeWithSelector(
            Target(address(evc)).impersonateTest.selector, address(evc), address(evc), seed, alice
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(Errors.EVC_ImpersonateReentrancy.selector);
        evc.impersonate{value: seed}(collateral, alice, seed, data);
    }

    function test_RevertIfTargetContractInvalid_Impersonate(address alice, uint256 seed) public {
        vm.assume(alice != address(0) && alice != address(evc));

        address controller = address(new Vault(evc));

        vm.prank(alice);
        evc.enableController(alice, controller);

        bytes memory data =
            abi.encodeWithSelector(Target.impersonateTest.selector, address(evc), address(evc), seed, alice);

        // target contract is the EVC
        address targetContract = address(evc);
        vm.deal(controller, seed);
        vm.prank(controller);
        vm.expectRevert(Errors.EVC_InvalidAddress.selector);
        evc.impersonate{value: seed}(targetContract, alice, seed, data);

        // target contract is the ERC1820 registry
        targetContract = 0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24;
        vm.prank(alice);
        evc.enableCollateral(alice, targetContract);

        vm.deal(controller, seed);
        vm.prank(controller);
        vm.expectRevert(Errors.EVC_InvalidAddress.selector);
        evc.impersonate{value: seed}(targetContract, alice, seed, data);
    }

    function test_RevertIfNoControllerEnabled_Impersonate(address alice, uint256 seed) public {
        vm.assume(alice != address(0) && alice != address(evc));

        address collateral = address(new Vault(evc));
        address controller = address(new Vault(evc));

        vm.assume(collateral != address(evc));

        vm.prank(alice);
        evc.enableCollateral(alice, collateral);

        bytes memory data =
            abi.encodeWithSelector(Target(collateral).impersonateTest.selector, address(evc), address(evc), seed, alice);

        vm.deal(controller, seed);
        vm.prank(controller);
        vm.expectRevert(Errors.EVC_ControllerViolation.selector);
        evc.impersonate{value: seed}(collateral, alice, seed, data);
    }

    function test_RevertIfMultipleControllersEnabled_Impersonate(address alice, uint256 seed) public {
        vm.assume(alice != address(0) && alice != address(evc));

        address collateral = address(new Vault(evc));
        address controller_1 = address(new Vault(evc));
        address controller_2 = address(new Vault(evc));

        vm.assume(collateral != address(evc));

        // mock checks deferred to enable multiple controllers
        evc.setCallDepth(1);

        vm.prank(alice);
        evc.enableCollateral(alice, collateral);

        vm.prank(alice);
        evc.enableController(alice, controller_1);

        vm.prank(alice);
        evc.enableController(alice, controller_2);

        bytes memory data =
            abi.encodeWithSelector(Target(collateral).impersonateTest.selector, address(evc), address(evc), seed, alice);

        vm.deal(controller_1, seed);
        vm.prank(controller_1);
        vm.expectRevert(Errors.EVC_ControllerViolation.selector);
        evc.impersonate{value: seed}(collateral, alice, seed, data);
    }

    function test_RevertIfMsgSenderIsNotEnabledController_Impersonate(
        address alice,
        address randomAddress,
        uint256 seed
    ) public {
        vm.assume(alice != address(0) && alice != address(evc));
        vm.assume(uint160(randomAddress) > 10 && randomAddress != address(evc));

        address collateral = address(new Vault(evc));
        address controller = address(new Vault(evc));

        vm.assume(collateral != address(evc));
        vm.assume(randomAddress != controller);

        vm.prank(alice);
        evc.enableCollateral(alice, collateral);

        vm.prank(alice);
        evc.enableController(alice, controller);

        bytes memory data =
            abi.encodeWithSelector(Target(collateral).impersonateTest.selector, address(evc), address(evc), seed, alice);

        vm.deal(randomAddress, seed);
        vm.prank(randomAddress);
        vm.expectRevert(abi.encodeWithSelector(Errors.EVC_NotAuthorized.selector));
        evc.impersonate{value: seed}(collateral, alice, seed, data);
    }

    function test_RevertIfTargetContractIsNotEnabledCollateral_Impersonate(
        address alice,
        address targetContract,
        uint256 seed
    ) public {
        vm.assume(alice != address(0) && alice != address(evc));
        vm.assume(targetContract != address(evc));

        address collateral = address(new Vault(evc));
        address controller = address(new Vault(evc));

        vm.assume(targetContract != collateral && targetContract != controller);

        vm.prank(alice);
        evc.enableCollateral(alice, collateral);

        vm.prank(alice);
        evc.enableController(alice, controller);

        bytes memory data =
            abi.encodeWithSelector(Target(collateral).impersonateTest.selector, address(evc), address(evc), seed, alice);

        vm.deal(controller, seed);
        vm.prank(controller);
        vm.expectRevert(abi.encodeWithSelector(Errors.EVC_NotAuthorized.selector));
        evc.impersonate{value: seed}(targetContract, alice, seed, data);
    }

    function test_RevertIfValueExceedsBalance_Impersonate(address alice, uint128 seed) public {
        vm.assume(alice != address(0) && alice != address(evc));
        vm.assume(seed > 0);

        address collateral = address(new Vault(evc));
        address controller = address(new Vault(evc));
        vm.assume(collateral != address(evc) && controller != address(evc));

        vm.prank(alice);
        evc.enableCollateral(alice, collateral);

        vm.prank(alice);
        evc.enableController(alice, controller);

        bytes memory data = abi.encodeWithSelector(
            Target(address(evc)).impersonateTest.selector, address(evc), address(evc), seed, alice
        );

        // reverts if value exceeds balance
        vm.deal(controller, seed);
        vm.prank(controller);
        vm.expectRevert(Errors.EVC_InvalidValue.selector);
        evc.impersonate{value: seed - 1}(collateral, alice, seed, data);

        // succeeds if value does not exceed balance
        vm.prank(controller);
        evc.impersonate{value: seed}(collateral, alice, seed, data);
    }

    function test_RevertIfInternalCallIsUnsuccessful_Impersonate(address alice) public {
        // call setUp() explicitly for Diligence Fuzzing tool to pass
        setUp();

        vm.assume(alice != address(0));
        vm.assume(alice != address(evc));

        address collateral = address(new Vault(evc));
        address controller = address(new Vault(evc));
        vm.assume(collateral != address(evc) && controller != address(evc));

        vm.prank(alice);
        evc.enableCollateral(alice, collateral);

        vm.prank(alice);
        evc.enableController(alice, controller);

        bytes memory data = abi.encodeWithSelector(Target(collateral).revertEmptyTest.selector);

        vm.prank(controller);
        vm.expectRevert(Errors.EVC_EmptyError.selector);
        evc.impersonate(collateral, alice, 0, data);
    }
}
