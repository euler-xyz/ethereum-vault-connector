// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../../utils/CreditVaultProtocolHarnessed.sol";

contract CreditVaultProtocolHandler is CreditVaultProtocolHarnessed {
    using Set for SetStorage;

    function handlerEnableController(address account, address vault) external {
        clearExpectedChecks();
        Vault(vault).clearChecks();

        super.enableController(account, vault);

        if (executionContext.batchDepth != BATCH_DEPTH__INIT) return;

        expectedAccountsChecked.push(
            account == address(0) ? msg.sender : account
        );
        verifyStorage();
        verifyAccountStatusChecks();
    }

    function handlerDisableController(address account) external {
        clearExpectedChecks();
        Vault(msg.sender).clearChecks();

        super.disableController(account);

        if (executionContext.batchDepth != BATCH_DEPTH__INIT) return;

        expectedAccountsChecked.push(
            account == address(0) ? msg.sender : account
        );
        verifyStorage();
        verifyAccountStatusChecks();
    }
}

contract ControllersManagementTest is Test {
    CreditVaultProtocolHandler internal cvp;

    event ControllerEnabled(
        address indexed account,
        address indexed controller
    );
    event ControllerDisabled(
        address indexed account,
        address indexed controller
    );

    function setUp() public {
        cvp = new CreditVaultProtocolHandler();
    }

    function test_ControllersManagement(
        address alice,
        uint8 subAccountId,
        uint seed
    ) public {
        vm.assume(alice != address(0));
        vm.assume(seed > 1000);

        address account = address(uint160(uint160(alice) ^ subAccountId));

        // test controllers management with use of an operator
        address msgSender = alice;
        if (
            seed % 2 == 0 &&
            !cvp.haveCommonOwner(account, address(uint160(seed)))
        ) {
            msgSender = address(uint160(seed));
            vm.prank(alice);
            cvp.setAccountOperator(account, msgSender, true);
        }

        // enabling controller
        address vault = address(new Vault(cvp));

        assertFalse(cvp.isControllerEnabled(account, vault));
        address[] memory controllersPre = cvp.getControllers(account);

        vm.prank(msgSender);
        vm.expectEmit(true, true, false, false, address(cvp));
        emit ControllerEnabled(account, vault);
        vm.recordLogs();
        cvp.handlerEnableController(account, vault);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        address[] memory controllersPost = cvp.getControllers(account);

        assertEq(logs.length, msgSender == alice ? 2 : 1);
        assertEq(controllersPost.length, controllersPre.length + 1);
        assertEq(controllersPost[controllersPost.length - 1], vault);
        assertTrue(cvp.isControllerEnabled(account, vault));

        // enabling the same controller again should succeed (duplicate will not be added and the event won't be emitted)
        assertTrue(cvp.isControllerEnabled(account, vault));
        controllersPre = cvp.getControllers(account);

        vm.prank(msgSender);
        vm.recordLogs();
        cvp.handlerEnableController(account, vault);
        logs = vm.getRecordedLogs();

        controllersPost = cvp.getControllers(account);

        assertEq(logs.length, 0);
        assertEq(controllersPost.length, controllersPre.length);
        assertEq(controllersPost[0], controllersPre[0]);
        assertTrue(cvp.isControllerEnabled(account, vault));

        // trying to enable second controller will throw on the account status check
        address otherVault = address(new Vault(cvp));

        vm.prank(msgSender);
        vm.expectRevert(CreditVaultProtocol.CVP_ControllerViolation.selector);
        cvp.handlerEnableController(account, otherVault);

        // only the controller vault can disable itself
        assertTrue(cvp.isControllerEnabled(account, vault));
        controllersPre = cvp.getControllers(account);

        vm.prank(msgSender);
        vm.expectEmit(true, true, false, false, address(cvp));
        emit ControllerDisabled(account, vault);
        Vault(vault).call(
            address(cvp),
            abi.encodeWithSelector(
                cvp.handlerDisableController.selector,
                account
            )
        );

        controllersPost = cvp.getControllers(account);

        assertEq(controllersPost.length, controllersPre.length - 1);
        assertEq(controllersPost.length, 0);
        assertFalse(cvp.isControllerEnabled(account, vault));
    }

    function test_RevertIfNotOwnerAndNotOperator_EnableController(
        address alice,
        address bob
    ) public {
        vm.assume(!cvp.haveCommonOwner(alice, bob));

        address vault = address(new Vault(cvp));

        vm.prank(alice);
        vm.expectRevert(CreditVaultProtocol.CVP_NotAuthorized.selector);
        cvp.handlerEnableController(bob, vault);

        vm.prank(bob);
        cvp.setAccountOperator(bob, alice, true);

        vm.prank(alice);
        cvp.handlerEnableController(bob, vault);
    }

    function test_RevertIfCTCCReentrancy_ControllersManagement(
        address alice
    ) public {
        address vault = address(new Vault(cvp));

        cvp.setControllerToCollateralCallLock(true);

        vm.prank(alice);
        vm.expectRevert(CreditVaultProtocol.CVP_CTCC_Reentancy.selector);
        cvp.enableController(alice, vault);

        cvp.setControllerToCollateralCallLock(false);

        vm.prank(alice);
        cvp.enableController(alice, vault);

        cvp.setControllerToCollateralCallLock(true);

        vm.prank(vault);
        vm.expectRevert(CreditVaultProtocol.CVP_CTCC_Reentancy.selector);
        cvp.disableController(alice);

        cvp.setControllerToCollateralCallLock(false);

        vm.prank(vault);
        cvp.disableController(alice);
    }

    function test_RevertIfAccountStatusViolated_ControllersManagement(
        address alice
    ) public {
        address vault = address(new Vault(cvp));

        Vault(vault).setAccountStatusState(1); // account status is violated

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultProtocol.CVP_AccountStatusViolation.selector,
                alice,
                "account status violation"
            )
        );
        cvp.handlerEnableController(alice, vault);

        vm.prank(alice);
        // succeeds as there's no controller to perform the account status check
        Vault(vault).call(
            address(cvp),
            abi.encodeWithSelector(cvp.handlerDisableController.selector, alice)
        );

        Vault(vault).setAccountStatusState(1); // account status is still violated

        vm.prank(alice);
        // succeeds as there's no controller to perform the account status check
        cvp.enableCollateral(alice, vault);

        Vault(vault).setAccountStatusState(0); // account status is no longer violated in order to enable controller

        vm.prank(alice);
        cvp.handlerEnableController(alice, vault);

        Vault(vault).setAccountStatusState(1); // account status is violated again

        vm.prank(alice);
        // it won't succeed as this time we have a controller so the account status check is performed
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultProtocol.CVP_AccountStatusViolation.selector,
                alice,
                "account status violation"
            )
        );
        cvp.enableCollateral(alice, vault);
    }
}
