// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../../utils/CreditVaultProtocolHarnessed.sol";

contract CreditVaultProtocolHandler is CreditVaultProtocolHarnessed {
    using Set for SetStorage;

    function handlerCallFromControllerToCollateral(
        address targetContract,
        address onBehalfOfAccount,
        address nextAccountStatusCheckIgnoredFrom,
        bytes calldata data
    ) public payable returns (bool success, bytes memory result) {
        (success, ) = msg.sender.call(
            abi.encodeWithSelector(Vault.clearChecks.selector)
        );
        clearExpectedChecks();

        (success, result) = super.callFromControllerToCollateral(
            targetContract,
            onBehalfOfAccount,
            nextAccountStatusCheckIgnoredFrom,
            data
        );

        verifyStorage();
        verifyVaultStatusChecks();
        verifyAccountStatusChecks();
    }
}

contract CallFromControllerToCollateralTest is Test {
    CreditVaultProtocolHandler internal cvp;

    function setUp() public {
        cvp = new CreditVaultProtocolHandler();
    }

    function test_CallFromControllerToCollateral(
        address alice,
        uint96 seed
    ) public {
        vm.assume(alice != address(0));

        address collateral = address(new Vault(cvp));
        address controller = address(new Vault(cvp));
        vm.assume(collateral != address(cvp));

        vm.prank(alice);
        cvp.enableCollateral(alice, collateral);

        vm.prank(alice);
        cvp.enableController(alice, controller);

        bytes memory data = abi.encodeWithSelector(
            Target(collateral).callFromControllerToCollateralTest.selector,
            address(cvp),
            address(cvp),
            seed,
            false,
            address(0),
            alice
        );

        hoax(controller, seed);
        (bool success, bytes memory result) = cvp
            .handlerCallFromControllerToCollateral{value: seed}(
            collateral,
            alice,
            address(0),
            data
        );

        assertTrue(success);
        assertEq(abi.decode(result, (uint)), seed);

        cvp.clearExpectedChecks();
        Vault(controller).clearChecks();

        // if called from a batch, the ETH value does not get forwarded
        data = abi.encodeWithSelector(
            Target(collateral).callFromControllerToCollateralTest.selector,
            address(cvp),
            address(cvp),
            0, // we're expecting ETH not to get forwarded
            true,
            address(0),
            alice
        );

        ICVP.BatchItem[] memory items = new ICVP.BatchItem[](1);

        items[0].allowError = false;
        items[0].onBehalfOfAccount = address(0);
        items[0].targetContract = address(cvp);
        items[0].msgValue = seed; // this value will get ignored
        items[0].data = abi.encodeWithSelector(
            cvp.callFromControllerToCollateral.selector,
            collateral,
            alice,
            address(0),
            data
        );

        hoax(controller, seed);
        cvp.batch(items);
        cvp.verifyVaultStatusChecks();
        cvp.verifyAccountStatusChecks();

        // this call should also succeed if the onBehalfOfAccount address passed is 0.
        // it should be replaced with msg.sender note that in this case the controller
        // tries to act on behalf of itself
        vm.prank(controller);
        cvp.enableCollateral(controller, collateral);

        vm.prank(controller);
        cvp.enableController(controller, controller);

        cvp.clearExpectedChecks();
        Vault(controller).clearChecks();

        data = abi.encodeWithSelector(
            Target(collateral).callFromControllerToCollateralTest.selector,
            address(cvp),
            address(cvp),
            seed,
            false,
            address(0),
            controller
        );

        hoax(controller, seed);
        (success, result) = cvp.handlerCallFromControllerToCollateral{
            value: seed
        }(collateral, address(0), address(0), data);

        assertTrue(success);
        assertEq(abi.decode(result, (uint)), seed);

        // verify ignoring the next account status check
        data = abi.encodeWithSelector(
            Target(collateral).callFromControllerToCollateralTest.selector,
            address(cvp),
            address(cvp),
            seed,
            false,
            collateral,
            alice
        );

        hoax(controller, seed);
        (success, result) = cvp.handlerCallFromControllerToCollateral{
            value: seed
        }(collateral, alice, collateral, data);

        assertTrue(success);
        assertEq(abi.decode(result, (uint)), seed);
    }

    function test_RevertIfCTCCReentrancy_CallFromControllerToCollateral(
        address alice,
        uint seed
    ) public {
        vm.assume(alice != address(0));

        address collateral = address(new Vault(cvp));
        address controller = address(new Vault(cvp));
        vm.assume(collateral != address(cvp));

        vm.prank(alice);
        cvp.enableCollateral(alice, collateral);

        vm.prank(alice);
        cvp.enableController(alice, controller);

        cvp.setControllerToCollateralCallLock(true);

        bytes memory data = abi.encodeWithSelector(
            Target(address(cvp)).callFromControllerToCollateralTest.selector,
            address(cvp),
            address(cvp),
            seed,
            false,
            address(0),
            alice
        );

        hoax(alice, seed);
        vm.expectRevert(CreditVaultProtocol.CVP_CTCC_Reentancy.selector);
        (bool success, ) = cvp.handlerCallFromControllerToCollateral{
            value: seed
        }(collateral, alice, address(0), data);

        assertFalse(success);
    }

    function test_RevertIfTargetContractInvalid_CallFromControllerToCollateral(
        address alice,
        uint seed
    ) public {
        vm.assume(alice != address(0));

        address controller = address(new Vault(cvp));

        vm.prank(alice);
        cvp.enableController(alice, controller);

        // target contract is the CVP
        bytes memory data = abi.encodeWithSelector(
            Target(address(cvp)).callFromControllerToCollateralTest.selector,
            address(cvp),
            address(cvp),
            seed,
            false,
            address(0),
            alice
        );

        hoax(alice, seed);
        vm.expectRevert(CreditVaultProtocol.CVP_InvalidAddress.selector);
        (bool success, ) = cvp.handlerCallFromControllerToCollateral{
            value: seed
        }(address(cvp), alice, address(0), data);

        assertFalse(success);
    }

    function test_RevertIfNoControllerEnabled_CallFromControllerToCollateral(
        address alice,
        uint seed
    ) public {
        vm.assume(alice != address(0));

        address collateral = address(new Vault(cvp));
        address controller = address(new Vault(cvp));

        vm.assume(collateral != address(cvp));

        vm.prank(alice);
        cvp.enableCollateral(alice, collateral);

        bytes memory data = abi.encodeWithSelector(
            Target(collateral).callFromControllerToCollateralTest.selector,
            address(cvp),
            address(cvp),
            seed,
            false,
            address(0),
            alice
        );

        hoax(controller, seed);
        vm.expectRevert(CreditVaultProtocol.CVP_ControllerViolation.selector);
        (bool success, ) = cvp.handlerCallFromControllerToCollateral{
            value: seed
        }(collateral, alice, address(0), data);

        assertFalse(success);
    }

    function test_RevertIfMultipleControllersEnabled_CallFromControllerToCollateral(
        address alice,
        uint seed
    ) public {
        vm.assume(alice != address(0));

        address collateral = address(new Vault(cvp));
        address controller_1 = address(new Vault(cvp));
        address controller_2 = address(new Vault(cvp));

        vm.assume(collateral != address(cvp));

        // mock checks deferred to enable multiple controllers
        cvp.setBatchDepth(2);

        vm.prank(alice);
        cvp.enableCollateral(alice, collateral);

        vm.prank(alice);
        cvp.enableController(alice, controller_1);

        vm.prank(alice);
        cvp.enableController(alice, controller_2);

        bytes memory data = abi.encodeWithSelector(
            Target(collateral).callFromControllerToCollateralTest.selector,
            address(cvp),
            address(cvp),
            seed,
            false,
            address(0),
            alice
        );

        hoax(controller_1, seed);
        vm.expectRevert(CreditVaultProtocol.CVP_ControllerViolation.selector);
        (bool success, ) = cvp.handlerCallFromControllerToCollateral{
            value: seed
        }(collateral, alice, address(0), data);

        assertFalse(success);
    }

    function test_RevertIfMsgSenderIsNotEnabledController_CallFromControllerToCollateral(
        address alice,
        address randomAddress,
        uint seed
    ) public {
        vm.assume(alice != address(0));
        vm.assume(uint160(randomAddress) > 10);

        address collateral = address(new Vault(cvp));
        address controller = address(new Vault(cvp));

        vm.assume(collateral != address(cvp));
        vm.assume(randomAddress != controller);

        vm.prank(alice);
        cvp.enableCollateral(alice, collateral);

        vm.prank(alice);
        cvp.enableController(alice, controller);

        bytes memory data = abi.encodeWithSelector(
            Target(collateral).callFromControllerToCollateralTest.selector,
            address(cvp),
            address(cvp),
            seed,
            false,
            address(0),
            alice
        );

        hoax(randomAddress, seed);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultProtocol.CVP_NotAuthorized.selector
            )
        );
        (bool success, ) = cvp.handlerCallFromControllerToCollateral{
            value: seed
        }(collateral, alice, address(0), data);

        assertFalse(success);
    }

    function test_RevertIfTargetContractIsNotEnabledCollateral_CallFromControllerToCollateral(
        address alice,
        address targetContract,
        uint seed
    ) public {
        vm.assume(alice != address(0));
        vm.assume(targetContract != address(cvp));

        address collateral = address(new Vault(cvp));
        address controller = address(new Vault(cvp));

        vm.assume(targetContract != collateral);

        vm.prank(alice);
        cvp.enableCollateral(alice, collateral);

        vm.prank(alice);
        cvp.enableController(alice, controller);

        bytes memory data = abi.encodeWithSelector(
            Target(collateral).callFromControllerToCollateralTest.selector,
            address(cvp),
            address(cvp),
            seed,
            false,
            address(0),
            alice
        );

        hoax(controller, seed);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultProtocol.CVP_NotAuthorized.selector
            )
        );
        (bool success, ) = cvp.handlerCallFromControllerToCollateral{
            value: seed
        }(targetContract, alice, address(0), data);

        assertFalse(success);
    }
}
