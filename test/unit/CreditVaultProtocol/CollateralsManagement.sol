// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../../utils/CreditVaultProtocolHarnessed.sol";

contract CreditVaultProtocolHandler is CreditVaultProtocolHarnessed {
    using Set for SetStorage;

    function handlerEnableCollateral(address account, address vault) external {
        clearExpectedChecks();

        super.enableCollateral(account, vault);

        if (executionContext.batchDepth != BATCH_DEPTH__INIT) return;

        expectedAccountsChecked.push(account);
        verifyStorage();
        verifyAccountStatusChecks();
    }

    function handlerDisableCollateral(address account, address vault) external {
        clearExpectedChecks();

        super.disableCollateral(account, vault);

        if (executionContext.batchDepth != BATCH_DEPTH__INIT) return;

        expectedAccountsChecked.push(account);
        verifyStorage();
        verifyAccountStatusChecks();
    }
}

contract CollateralsManagementTest is Test {
    CreditVaultProtocolHandler internal cvp;

    function setUp() public {
        cvp = new CreditVaultProtocolHandler();
    }

    function test_CollateralsManagement(address alice, uint8 subAccountId, uint8 numberOfVaults, uint seed) public {
        vm.assume(alice != address(0));
        vm.assume(numberOfVaults > 0 && numberOfVaults <= Set.MAX_ELEMENTS);
        vm.assume(seed > 1000);

        address account = address(uint160(uint160(alice) ^ subAccountId));

        vm.expectRevert(CreditVaultProtocol.CVP_AccountOwnerNotRegistered.selector);
        cvp.getAccountOwner(account);

        // test collaterals management with use of an operator
        address msgSender = alice;
        if (seed % 2 == 0 && !cvp.haveCommonOwner(account, address(uint160(seed)))) {
            msgSender = address(uint160(seed));
            vm.prank(alice);
            cvp.setAccountOperator(account, msgSender, true);
            assertEq(cvp.getAccountOwner(account), alice);
        }

        // enable a controller to check if account status check works properly
        address controller = address(new Vault(cvp));
        if (seed % 3 == 0) {
            vm.prank(alice);
            cvp.enableController(account, controller);
            assertEq(cvp.getAccountOwner(account), alice);
        }

        // enabling collaterals
        for (uint i = 1; i <= numberOfVaults; ++i) {
            Vault(controller).clearChecks();
            address[] memory collateralsPre = cvp.getCollaterals(account);

            address vault = i % 5 == 0
                ? collateralsPre[seed % collateralsPre.length]
                : address(new Vault(cvp));

            bool alreadyEnabled = cvp.isCollateralEnabled(account, vault);

            assert((alreadyEnabled && i % 5 == 0) || (!alreadyEnabled && i % 5 != 0));

            vm.prank(msgSender);
            cvp.handlerEnableCollateral(account, vault);

            address[] memory collateralsPost = cvp.getCollaterals(account);

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
        while (cvp.getCollaterals(account).length > 0) {
            Vault(controller).clearChecks();
            address[] memory collateralsPre = cvp.getCollaterals(account);
            address vault = collateralsPre[seed % collateralsPre.length];

            vm.prank(msgSender);
            cvp.handlerDisableCollateral(account, vault);

            address[] memory collateralsPost = cvp.getCollaterals(account);

            assertEq(collateralsPost.length, collateralsPre.length - 1);

            for (uint j = 0; j < collateralsPost.length; ++j) {
                assertNotEq(collateralsPost[j], vault);
            }
        }
    }

    function test_RevertIfNotOwnerAndNotOperator_CollateralsManagement(address alice, address bob) public {
        vm.assume(!cvp.haveCommonOwner(alice, bob));

        address vault = address(new Vault(cvp));

        vm.prank(alice);
        vm.expectRevert(CreditVaultProtocol.CVP_NotAuthorized.selector);
        cvp.handlerEnableCollateral(bob, vault);

        vm.prank(alice);
        vm.expectRevert(CreditVaultProtocol.CVP_NotAuthorized.selector);
        cvp.handlerDisableCollateral(bob, vault);

        vm.prank(bob);
        cvp.setAccountOperator(bob, alice, true);

        vm.prank(alice);
        cvp.handlerEnableCollateral(bob, vault);

        vm.prank(alice);
        cvp.handlerDisableCollateral(bob, vault);
    }

    function test_RevertIfAccountStatusViolated_CollateralsManagement(address alice) public {
        address vault = address(new Vault(cvp));
        address controller = address(new Vault(cvp));

        vm.prank(alice);
        cvp.enableController(alice, controller);

        Vault(controller).setAccountStatusState(1); // account status is violated

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultProtocol.CVP_AccountStatusViolation.selector,
                alice,
                "account status violation"
            )
        );
        cvp.handlerEnableCollateral(alice, vault);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultProtocol.CVP_AccountStatusViolation.selector,
                alice,
                "account status violation"
            )
        );
        cvp.handlerDisableCollateral(alice, vault);

        Vault(controller).setAccountStatusState(0); // account status is NOT violated

        Vault(controller).clearChecks();
        vm.prank(alice);
        cvp.handlerEnableCollateral(alice, vault);

        Vault(controller).clearChecks();
        vm.prank(alice);
        cvp.handlerDisableCollateral(alice, vault);
    }
}
