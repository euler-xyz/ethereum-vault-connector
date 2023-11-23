// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../evc/EthereumVaultConnectorHarness.sol";

contract EthereumVaultConnectorHandler is EthereumVaultConnectorHarness {
    using ExecutionContext for EC;
    using Set for SetStorage;

    function handlerEnableCollateral(address account, address vault) external {
        clearExpectedChecks();

        super.enableCollateral(account, vault);

        if (executionContext.areChecksDeferred()) return;

        expectedAccountsChecked.push(account);

        verifyAccountStatusChecks();
    }

    function handlerDisableCollateral(address account, address vault) external {
        clearExpectedChecks();

        super.disableCollateral(account, vault);

        if (executionContext.areChecksDeferred()) return;

        expectedAccountsChecked.push(account);

        verifyAccountStatusChecks();
    }
}

contract CollateralsManagementTest is Test {
    EthereumVaultConnectorHandler internal evc;

    event CollateralStatus(address indexed account, address indexed collateral, bool enabled);

    function setUp() public {
        evc = new EthereumVaultConnectorHandler();
    }

    function test_CollateralsManagement(address alice, uint8 subAccountId, uint8 numberOfVaults, uint256 seed) public {
        // call setUp() explicitly for Diligence Fuzzing tool to pass
        setUp();

        vm.assume(alice != address(0) && alice != address(evc));
        vm.assume(numberOfVaults > 0 && numberOfVaults <= Set.MAX_ELEMENTS);
        vm.assume(seed > 1000);

        address account = address(uint160(uint160(alice) ^ subAccountId));

        vm.expectRevert(Errors.EVC_AccountOwnerNotRegistered.selector);
        evc.getAccountOwner(account);

        // test collaterals management with use of an operator
        address msgSender = alice;
        if (seed % 2 == 0 && !evc.haveCommonOwner(account, address(uint160(seed)))) {
            msgSender = address(uint160(uint256(keccak256(abi.encodePacked(seed)))));
            vm.prank(alice);
            evc.setAccountOperator(account, msgSender, true);
            assertEq(evc.getAccountOwner(account), alice);
        }

        // enable a controller to check if account status check works properly
        address controller = address(new Vault(evc));
        if (seed % 3 == 0) {
            vm.prank(alice);
            evc.enableController(account, controller);
            assertEq(evc.getAccountOwner(account), alice);
        }

        // enabling collaterals
        for (uint256 i = 1; i <= numberOfVaults; ++i) {
            Vault(controller).clearChecks();
            address[] memory collateralsPre = evc.getCollaterals(account);

            address vault = i % 5 == 0 ? collateralsPre[seed % collateralsPre.length] : address(new Vault(evc));

            bool alreadyEnabled = evc.isCollateralEnabled(account, vault);

            assert((alreadyEnabled && i % 5 == 0) || (!alreadyEnabled && i % 5 != 0));

            if (!alreadyEnabled) {
                vm.expectEmit(true, true, false, true, address(evc));
                emit CollateralStatus(account, vault, true);
            }
            vm.prank(msgSender);
            evc.handlerEnableCollateral(account, vault);

            address[] memory collateralsPost = evc.getCollaterals(account);

            if (alreadyEnabled) {
                assertEq(collateralsPost.length, collateralsPre.length);
            } else {
                assertEq(collateralsPost.length, collateralsPre.length + 1);
                assertEq(collateralsPost[collateralsPost.length - 1], vault);
            }

            for (uint256 j = 0; j < collateralsPre.length; ++j) {
                assertEq(collateralsPre[j], collateralsPost[j]);
            }
        }

        // disabling collaterals
        while (evc.getCollaterals(account).length > 0) {
            Vault(controller).clearChecks();
            address[] memory collateralsPre = evc.getCollaterals(account);
            address vault = collateralsPre[seed % collateralsPre.length];

            vm.expectEmit(true, true, false, true, address(evc));
            emit CollateralStatus(account, vault, false);
            vm.prank(msgSender);
            evc.handlerDisableCollateral(account, vault);

            address[] memory collateralsPost = evc.getCollaterals(account);

            assertEq(collateralsPost.length, collateralsPre.length - 1);

            for (uint256 j = 0; j < collateralsPost.length; ++j) {
                assertNotEq(collateralsPost[j], vault);
            }
        }
    }

    function test_RevertIfNotOwnerOrNotOperator_CollateralsManagement(address alice, address bob) public {
        vm.assume(alice != address(0) && alice != address(evc) && bob != address(0) && bob != address(evc));
        vm.assume(!evc.haveCommonOwner(alice, bob));

        address vault = address(new Vault(evc));

        vm.prank(alice);
        vm.expectRevert(Errors.EVC_NotAuthorized.selector);
        evc.enableCollateral(bob, vault);

        vm.prank(alice);
        vm.expectRevert(Errors.EVC_NotAuthorized.selector);
        evc.disableCollateral(bob, vault);

        vm.prank(bob);
        evc.setAccountOperator(bob, alice, true);

        vm.prank(alice);
        evc.enableCollateral(bob, vault);

        vm.prank(alice);
        evc.disableCollateral(bob, vault);
    }

    function test_RevertIfChecksReentrancy_CollateralsManagement(address alice) public {
        vm.assume(alice != address(evc));
        address vault = address(new Vault(evc));

        evc.setChecksLock(true);

        vm.prank(alice);
        vm.expectRevert(Errors.EVC_ChecksReentrancy.selector);
        evc.enableCollateral(alice, vault);

        evc.setChecksLock(false);

        vm.prank(alice);
        evc.enableCollateral(alice, vault);

        evc.setChecksLock(true);

        vm.prank(alice);
        vm.expectRevert(Errors.EVC_ChecksReentrancy.selector);
        evc.disableCollateral(alice, vault);

        evc.setChecksLock(false);

        vm.prank(alice);
        evc.disableCollateral(alice, vault);
    }

    function test_RevertIfImpersonateReentrancy_CollateralsManagement(address alice) public {
        vm.assume(alice != address(evc));
        address vault = address(new Vault(evc));

        evc.setImpersonateLock(true);

        vm.prank(alice);
        vm.expectRevert(Errors.EVC_ImpersonateReentrancy.selector);
        evc.enableCollateral(alice, vault);

        evc.setImpersonateLock(false);

        vm.prank(alice);
        evc.enableCollateral(alice, vault);

        evc.setImpersonateLock(true);

        vm.prank(alice);
        vm.expectRevert(Errors.EVC_ImpersonateReentrancy.selector);
        evc.disableCollateral(alice, vault);

        evc.setImpersonateLock(false);

        vm.prank(alice);
        evc.disableCollateral(alice, vault);
    }

    function test_RevertIfInvalidVault_CollateralsManagement(address alice) public {
        vm.assume(alice != address(evc));
        vm.prank(alice);
        vm.expectRevert(Errors.EVC_InvalidAddress.selector);
        evc.enableCollateral(alice, address(evc));
    }

    function test_RevertIfAccountStatusViolated_CollateralsManagement(address alice) public {
        vm.assume(alice != address(evc));

        address vault = address(new Vault(evc));
        address controller = address(new Vault(evc));

        vm.prank(alice);
        evc.enableController(alice, controller);

        Vault(controller).setAccountStatusState(1); // account status is violated

        vm.prank(alice);
        vm.expectRevert(bytes("account status violation"));
        evc.enableCollateral(alice, vault);

        vm.prank(alice);
        vm.expectRevert(bytes("account status violation"));
        evc.disableCollateral(alice, vault);

        Vault(controller).setAccountStatusState(0); // account status is NOT violated

        Vault(controller).clearChecks();
        vm.prank(alice);
        evc.enableCollateral(alice, vault);

        Vault(controller).clearChecks();
        vm.prank(alice);
        evc.disableCollateral(alice, vault);
    }
}
