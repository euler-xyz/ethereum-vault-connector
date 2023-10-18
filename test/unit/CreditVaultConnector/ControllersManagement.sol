// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../cvc/CreditVaultConnectorHarness.sol";

contract CreditVaultConnectorHandler is CreditVaultConnectorHarness {
    using ExecutionContext for EC;
    using Set for SetStorage;

    function handlerEnableController(address account, address vault) external {
        clearExpectedChecks();
        Vault(vault).clearChecks();

        super.enableController(account, vault);

        if (executionContext.isInBatch()) return;

        expectedAccountsChecked.push(account);

        verifyAccountStatusChecks();
    }

    function handlerDisableController(address account) external {
        clearExpectedChecks();
        Vault(msg.sender).clearChecks();

        super.disableController(account);

        if (executionContext.isInBatch()) return;

        expectedAccountsChecked.push(account);

        verifyAccountStatusChecks();
    }
}

contract ControllersManagementTest is Test {
    CreditVaultConnectorHandler internal cvc;

    event ControllerStatus(
        address indexed account,
        address indexed controller,
        bool indexed enabled
    );

    function setUp() public {
        cvc = new CreditVaultConnectorHandler();
    }

    function test_ControllersManagement(
        address alice,
        uint8 subAccountId,
        uint seed
    ) public {
        vm.assume(alice != address(0) && alice != address(cvc));
        vm.assume(seed > 1000);

        address account = address(uint160(uint160(alice) ^ subAccountId));

        // test controllers management with use of an operator
        address msgSender = alice;
        if (
            seed % 2 == 0 &&
            !cvc.haveCommonOwner(account, address(uint160(seed)))
        ) {
            msgSender = address(uint160(uint(keccak256(abi.encode(seed)))));
            vm.prank(alice);
            cvc.setAccountOperator(account, msgSender, true);
        }

        // enabling controller
        address vault = address(new Vault(cvc));

        assertFalse(cvc.isControllerEnabled(account, vault));
        address[] memory controllersPre = cvc.getControllers(account);

        vm.prank(msgSender);
        vm.expectEmit(true, true, true, false, address(cvc));
        emit ControllerStatus(account, vault, true);
        vm.recordLogs();
        cvc.handlerEnableController(account, vault);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        address[] memory controllersPost = cvc.getControllers(account);

        assertEq(logs.length, msgSender == alice ? 2 : 1);
        assertEq(controllersPost.length, controllersPre.length + 1);
        assertEq(controllersPost[controllersPost.length - 1], vault);
        assertTrue(cvc.isControllerEnabled(account, vault));

        // enabling the same controller again should succeed (duplicate will not be added and the event won't be emitted)
        assertTrue(cvc.isControllerEnabled(account, vault));
        controllersPre = cvc.getControllers(account);

        vm.prank(msgSender);
        vm.recordLogs();
        cvc.handlerEnableController(account, vault);
        logs = vm.getRecordedLogs();

        controllersPost = cvc.getControllers(account);

        assertEq(logs.length, 0);
        assertEq(controllersPost.length, controllersPre.length);
        assertEq(controllersPost[0], controllersPre[0]);
        assertTrue(cvc.isControllerEnabled(account, vault));

        // trying to enable second controller will throw on the account status check
        address otherVault = address(new Vault(cvc));

        vm.prank(msgSender);
        vm.expectRevert(CreditVaultConnector.CVC_ControllerViolation.selector);
        cvc.handlerEnableController(account, otherVault);

        // only the controller vault can disable itself
        assertTrue(cvc.isControllerEnabled(account, vault));
        controllersPre = cvc.getControllers(account);

        vm.prank(msgSender);
        vm.expectEmit(true, true, true, false, address(cvc));
        emit ControllerStatus(account, vault, false);
        Vault(vault).call(
            address(cvc),
            abi.encodeWithSelector(
                cvc.handlerDisableController.selector,
                account
            )
        );

        controllersPost = cvc.getControllers(account);

        assertEq(controllersPost.length, controllersPre.length - 1);
        assertEq(controllersPost.length, 0);
        assertFalse(cvc.isControllerEnabled(account, vault));
    }

    function test_RevertIfNotOwnerOrNotOperator_EnableController(
        address alice,
        address bob
    ) public {
        vm.assume(
            alice != address(0) &&
                alice != address(cvc) &&
                bob != address(0) &&
                bob != address(cvc)
        );
        vm.assume(!cvc.haveCommonOwner(alice, bob));

        address vault = address(new Vault(cvc));

        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.handlerEnableController(bob, vault);

        vm.prank(bob);
        cvc.setAccountOperator(bob, alice, true);

        vm.prank(alice);
        cvc.handlerEnableController(bob, vault);
    }

    function test_RevertIfProgressReentrancy_ControllersManagement(
        address alice
    ) public {
        vm.assume(alice != address(cvc));

        address vault = address(new Vault(cvc));

        cvc.setChecksLock(true);

        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_ChecksReentrancy.selector);
        cvc.enableController(alice, vault);

        cvc.setChecksLock(false);

        vm.prank(alice);
        cvc.enableController(alice, vault);

        cvc.setChecksLock(true);

        vm.prank(vault);
        vm.expectRevert(CreditVaultConnector.CVC_ChecksReentrancy.selector);
        cvc.disableController(alice);

        cvc.setChecksLock(false);

        vm.prank(vault);
        cvc.disableController(alice);
    }

    function test_RevertIfImpersonateReentrancy_ControllersManagement(
        address alice
    ) public {
        vm.assume(alice != address(cvc));

        address vault = address(new Vault(cvc));

        cvc.setImpersonateLock(true);

        vm.prank(alice);
        vm.expectRevert(
            CreditVaultConnector.CVC_ImpersonateReentrancy.selector
        );
        cvc.enableController(alice, vault);

        cvc.setImpersonateLock(false);

        vm.prank(alice);
        cvc.enableController(alice, vault);

        cvc.setImpersonateLock(true);

        vm.prank(vault);
        vm.expectRevert(
            CreditVaultConnector.CVC_ImpersonateReentrancy.selector
        );
        cvc.disableController(alice);

        cvc.setImpersonateLock(false);

        vm.prank(vault);
        cvc.disableController(alice);
    }

    function test_RevertIfInvalidVault_ControllersManagement(
        address alice
    ) public {
        vm.assume(alice != address(cvc));
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidAddress.selector);
        cvc.enableController(alice, address(cvc));
    }

    function test_RevertIfAccountStatusViolated_ControllersManagement(
        address alice
    ) public {
        vm.assume(alice != address(cvc));

        address vault = address(new Vault(cvc));

        Vault(vault).setAccountStatusState(1); // account status is violated

        vm.prank(alice);
        vm.expectRevert("account status violation");
        cvc.handlerEnableController(alice, vault);

        vm.prank(alice);
        // succeeds as there's no controller to perform the account status check
        Vault(vault).call(
            address(cvc),
            abi.encodeWithSelector(cvc.handlerDisableController.selector, alice)
        );

        Vault(vault).setAccountStatusState(1); // account status is still violated

        vm.prank(alice);
        // succeeds as there's no controller to perform the account status check
        cvc.enableCollateral(alice, vault);

        Vault(vault).setAccountStatusState(0); // account status is no longer violated in order to enable controller

        vm.prank(alice);
        cvc.handlerEnableController(alice, vault);

        Vault(vault).setAccountStatusState(1); // account status is violated again

        vm.prank(alice);
        // it won't succeed as this time we have a controller so the account status check is performed
        vm.expectRevert("account status violation");
        cvc.enableCollateral(alice, vault);
    }
}
