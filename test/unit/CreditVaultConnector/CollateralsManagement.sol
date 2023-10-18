// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../cvc/CreditVaultConnectorHarness.sol";

contract CreditVaultConnectorHandler is CreditVaultConnectorHarness {
    using ExecutionContext for EC;
    using Set for SetStorage;

    function handlerEnableCollateral(address account, address vault) external {
        clearExpectedChecks();

        super.enableCollateral(account, vault);

        if (executionContext.isInBatch()) return;

        expectedAccountsChecked.push(account);

        verifyAccountStatusChecks();
    }

    function handlerDisableCollateral(address account, address vault) external {
        clearExpectedChecks();

        super.disableCollateral(account, vault);

        if (executionContext.isInBatch()) return;

        expectedAccountsChecked.push(account);

        verifyAccountStatusChecks();
    }
}

contract CollateralsManagementTest is Test {
    CreditVaultConnectorHandler internal cvc;

    function setUp() public {
        cvc = new CreditVaultConnectorHandler();
    }

    function test_CollateralsManagement(
        address alice,
        uint8 subAccountId,
        uint8 numberOfVaults,
        uint seed
    ) public {
        vm.assume(alice != address(0) && alice != address(cvc));
        vm.assume(numberOfVaults > 0 && numberOfVaults <= Set.MAX_ELEMENTS);
        vm.assume(seed > 1000);

        // call setUp() explicitly for Dilligence Fuzzing tool to pass
        setUp();

        address account = address(uint160(uint160(alice) ^ subAccountId));

        vm.expectRevert(
            CreditVaultConnector.CVC_AccountOwnerNotRegistered.selector
        );
        cvc.getAccountOwner(account);

        // test collaterals management with use of an operator
        address msgSender = alice;
        if (
            seed % 2 == 0 &&
            !cvc.haveCommonOwner(account, address(uint160(seed)))
        ) {
            msgSender = address(
                uint160(uint(keccak256(abi.encodePacked(seed))))
            );
            vm.prank(alice);
            cvc.setAccountOperator(account, msgSender, true);
            assertEq(cvc.getAccountOwner(account), alice);
        }

        // enable a controller to check if account status check works properly
        address controller = address(new Vault(cvc));
        if (seed % 3 == 0) {
            vm.prank(alice);
            cvc.enableController(account, controller);
            assertEq(cvc.getAccountOwner(account), alice);
        }

        // enabling collaterals
        for (uint i = 1; i <= numberOfVaults; ++i) {
            Vault(controller).clearChecks();
            address[] memory collateralsPre = cvc.getCollaterals(account);

            address vault = i % 5 == 0
                ? collateralsPre[seed % collateralsPre.length]
                : address(new Vault(cvc));

            bool alreadyEnabled = cvc.isCollateralEnabled(account, vault);

            assert(
                (alreadyEnabled && i % 5 == 0) ||
                    (!alreadyEnabled && i % 5 != 0)
            );

            vm.prank(msgSender);
            cvc.handlerEnableCollateral(account, vault);

            address[] memory collateralsPost = cvc.getCollaterals(account);

            if (alreadyEnabled) {
                assertEq(collateralsPost.length, collateralsPre.length);
            } else {
                assertEq(collateralsPost.length, collateralsPre.length + 1);
                assertEq(collateralsPost[collateralsPost.length - 1], vault);
            }

            for (uint j = 0; j < collateralsPre.length; ++j) {
                assertEq(collateralsPre[j], collateralsPost[j]);
            }
        }

        // disabling collaterals
        while (cvc.getCollaterals(account).length > 0) {
            Vault(controller).clearChecks();
            address[] memory collateralsPre = cvc.getCollaterals(account);
            address vault = collateralsPre[seed % collateralsPre.length];

            vm.prank(msgSender);
            cvc.handlerDisableCollateral(account, vault);

            address[] memory collateralsPost = cvc.getCollaterals(account);

            assertEq(collateralsPost.length, collateralsPre.length - 1);

            for (uint j = 0; j < collateralsPost.length; ++j) {
                assertNotEq(collateralsPost[j], vault);
            }
        }
    }

    function test_RevertIfNotOwnerOrNotOperator_CollateralsManagement(
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
        cvc.enableCollateral(bob, vault);

        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.disableCollateral(bob, vault);

        vm.prank(bob);
        cvc.setAccountOperator(bob, alice, true);

        vm.prank(alice);
        cvc.enableCollateral(bob, vault);

        vm.prank(alice);
        cvc.disableCollateral(bob, vault);
    }

    function test_RevertIfChecksReentrancy_CollateralsManagement(
        address alice
    ) public {
        vm.assume(alice != address(cvc));
        address vault = address(new Vault(cvc));

        cvc.setChecksLock(true);

        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_ChecksReentrancy.selector);
        cvc.enableCollateral(alice, vault);

        cvc.setChecksLock(false);

        vm.prank(alice);
        cvc.enableCollateral(alice, vault);

        cvc.setChecksLock(true);

        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_ChecksReentrancy.selector);
        cvc.disableCollateral(alice, vault);

        cvc.setChecksLock(false);

        vm.prank(alice);
        cvc.disableCollateral(alice, vault);
    }

    function test_RevertIfImpersonateReentrancy_CollateralsManagement(
        address alice
    ) public {
        vm.assume(alice != address(cvc));
        address vault = address(new Vault(cvc));

        cvc.setImpersonateLock(true);

        vm.prank(alice);
        vm.expectRevert(
            CreditVaultConnector.CVC_ImpersonateReentrancy.selector
        );
        cvc.enableCollateral(alice, vault);

        cvc.setImpersonateLock(false);

        vm.prank(alice);
        cvc.enableCollateral(alice, vault);

        cvc.setImpersonateLock(true);

        vm.prank(alice);
        vm.expectRevert(
            CreditVaultConnector.CVC_ImpersonateReentrancy.selector
        );
        cvc.disableCollateral(alice, vault);

        cvc.setImpersonateLock(false);

        vm.prank(alice);
        cvc.disableCollateral(alice, vault);
    }

    function test_RevertIfInvalidVault_CollateralsManagement(
        address alice
    ) public {
        vm.assume(alice != address(cvc));
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidAddress.selector);
        cvc.enableCollateral(alice, address(cvc));
    }

    function test_RevertIfAccountStatusViolated_CollateralsManagement(
        address alice
    ) public {
        vm.assume(alice != address(cvc));

        address vault = address(new Vault(cvc));
        address controller = address(new Vault(cvc));

        vm.prank(alice);
        cvc.enableController(alice, controller);

        Vault(controller).setAccountStatusState(1); // account status is violated

        vm.prank(alice);
        vm.expectRevert(bytes("account status violation"));
        cvc.enableCollateral(alice, vault);

        vm.prank(alice);
        vm.expectRevert(bytes("account status violation"));
        cvc.disableCollateral(alice, vault);

        Vault(controller).setAccountStatusState(0); // account status is NOT violated

        Vault(controller).clearChecks();
        vm.prank(alice);
        cvc.enableCollateral(alice, vault);

        Vault(controller).clearChecks();
        vm.prank(alice);
        cvc.disableCollateral(alice, vault);
    }
}
