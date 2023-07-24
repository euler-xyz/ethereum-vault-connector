// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../../utils/CreditVaultProtocolHarnessed.sol";

contract AccountStatusTest is Test {
    CreditVaultProtocolHarnessed internal cvp;

    function setUp() public {
        cvp = new CreditVaultProtocolHarnessed();
    }

    function test_CheckAccountsStatus(address[] memory accounts, bool allStatusesValid) external {
        for (uint i = 0; i < accounts.length; i++) {
            address account = accounts[i];

            // avoid duplicate entries in the accounts array not to enable multiple
            // controllers for the same account
            bool seen = false;
            for (uint j = 0; j < i; j++) {
                if (accounts[j] == account) {
                    seen = true;
                    break;
                }
            }
            if (seen) continue;

            address controller = address(new Vault(cvp));

            vm.prank(account);
            cvp.enableController(account, controller);

            // check all the options: account state is ok, account state is violated with
            // controller returning false and reverting
            Vault(controller).setAccountStatusState(
                allStatusesValid
                ? 0
                : uint160(account) % 3 == 0
                    ? 0
                    : uint160(account) % 3 == 1
                        ? 1
                        : 2
            );

            if (!(allStatusesValid || uint160(account) % 3 == 0)) {
                assertFalse(cvp.checkAccountStatus(account));
            } else {
                assertTrue(cvp.checkAccountStatus(account));
            }
        }

        bool[] memory isValid = cvp.checkAccountsStatus(accounts);
        for (uint i = 0; i < accounts.length; i++) {
            address account = accounts[i];

            if (!(allStatusesValid || uint160(account) % 3 == 0)) assertFalse(isValid[i]);
            else assertTrue(isValid[i]);
        }
    }

    function test_RequireAccountsStatusCheck(uint8 numberOfAccounts, bytes memory seed, bool allStatusesValid) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);
        
        address[] memory accounts = new address[](numberOfAccounts);
        address[] memory controllers = new address[](numberOfAccounts);
        for (uint i = 0; i < numberOfAccounts; i++) {
            accounts[i] = address(uint160(uint(keccak256(abi.encode(i, seed)))));
            controllers[i] = address(new Vault(cvp));
        }

        uint invalidAccountsCounter;
        address[] memory invalidAccounts = new address[](numberOfAccounts);

        for (uint i = 0; i < numberOfAccounts; i++) {
            address account = accounts[i];
            address controller = controllers[i];

            vm.prank(account);
            cvp.enableController(account, controller);
            Vault(controller).clearChecks();
            cvp.clearExpectedChecks();

            // check all the options: account state is ok, account state is violated with
            // controller returning false and reverting
            Vault(controller).setAccountStatusState(
                allStatusesValid
                ? 0
                : uint160(account) % 3 == 0
                    ? 0
                    : uint160(account) % 3 == 1
                        ? 1
                        : 2
            );

            // account status check will be performed because the account status check is not ordered 
            // to be ignored or the check is not being scheduled for current onBehalfOfAccount
            cvp.setIgnoreAccountStatusCheck(true);
            cvp.setOnBehalfOfAccount(address(0));

            if (!(allStatusesValid || uint160(account) % 3 == 0)) {
                // for later checks
                invalidAccounts[invalidAccountsCounter++] = accounts[i];

                vm.expectRevert(abi.encodeWithSelector(
                    CreditVaultProtocol.CVP_AccountStatusViolation.selector,
                    account,
                    uint160(account) % 3 == 1
                        ? bytes("account status violation")
                        : abi.encodeWithSignature("Error(string)", bytes("invalid account"))
                ));
            }

            cvp.requireAccountStatusCheck(account);

            if (allStatusesValid || uint160(account) % 3 == 0) cvp.verifyAccountStatusChecks();

            Vault(controller).clearChecks();
            cvp.clearExpectedChecks();

            // try other combinations of the conditions; account status check still being performed
            cvp.setIgnoreAccountStatusCheck(false);
            cvp.setOnBehalfOfAccount(account);

            if (!(allStatusesValid || uint160(account) % 3 == 0)) {
                vm.expectRevert(abi.encodeWithSelector(
                    CreditVaultProtocol.CVP_AccountStatusViolation.selector,
                    account,
                    uint160(account) % 3 == 1
                        ? bytes("account status violation")
                        : abi.encodeWithSignature("Error(string)", bytes("invalid account"))
                ));
            }

            cvp.requireAccountStatusCheck(account);

            if (allStatusesValid || uint160(account) % 3 == 0) cvp.verifyAccountStatusChecks();

            Vault(controller).clearChecks();
            cvp.clearExpectedChecks();

            // account status check will no longer be performed because the account status check is ordered 
            // to be ignored and the check is being scheduled for current onBehalfOfAccount
            cvp.setIgnoreAccountStatusCheck(true);
            cvp.setOnBehalfOfAccount(account);

            cvp.requireAccountStatusCheck(account);
            cvp.verifyAccountStatusChecks();

            Vault(controller).clearChecks();
            cvp.clearExpectedChecks();
        }

        // setup
        cvp.setIgnoreAccountStatusCheck(true);
        cvp.setOnBehalfOfAccount(address(0));

        // if there's any account which is not valid, the whole transaction should revert
        if (invalidAccountsCounter > 0) {
            vm.expectRevert(abi.encodeWithSelector(
                CreditVaultProtocol.CVP_AccountStatusViolation.selector,
                invalidAccounts[0],
                uint160(invalidAccounts[0]) % 3 == 1
                    ? bytes("account status violation")
                    : abi.encodeWithSignature("Error(string)", bytes("invalid account"))
            ));
        }

        cvp.requireAccountsStatusCheck(accounts);
        cvp.verifyAccountStatusChecks();

        for (uint i = 0; i < controllers.length; ++i) {Vault(controllers[i]).clearChecks();}
        cvp.clearExpectedChecks();

        // setup
        cvp.setIgnoreAccountStatusCheck(false);
        cvp.setOnBehalfOfAccount(invalidAccountsCounter > 0 ? invalidAccounts[0] : address(0));

        // if there's any account which is not valid, the whole transaction should revert
        if (invalidAccountsCounter > 0) {
            vm.expectRevert(abi.encodeWithSelector(
                CreditVaultProtocol.CVP_AccountStatusViolation.selector,
                invalidAccounts[0],
                uint160(invalidAccounts[0]) % 3 == 1
                    ? bytes("account status violation")
                    : abi.encodeWithSignature("Error(string)", bytes("invalid account"))
            ));
        }

        cvp.requireAccountsStatusCheck(accounts);
        cvp.verifyAccountStatusChecks();
        
        for (uint i = 0; i < controllers.length; ++i) {Vault(controllers[i]).clearChecks();}
        cvp.clearExpectedChecks();

        // setup
        cvp.setIgnoreAccountStatusCheck(true);
        cvp.setOnBehalfOfAccount(invalidAccountsCounter > 0 ? invalidAccounts[0] : address(0));

        // if there's more than one account which is not valid, the whole transaction should revert.
        // if there's only one account which is not valid, the transaction should succeed because the check
        // for the invalid account is being ignored
        if (invalidAccountsCounter > 1) {
            vm.expectRevert(abi.encodeWithSelector(
                CreditVaultProtocol.CVP_AccountStatusViolation.selector,
                invalidAccounts[1],
                uint160(invalidAccounts[1]) % 3 == 1
                    ? bytes("account status violation")
                    : abi.encodeWithSignature("Error(string)", bytes("invalid account"))
            ));
        }

        cvp.requireAccountsStatusCheck(accounts);
        cvp.verifyAccountStatusChecks();
    }

    function test_WhenDeferred_RequireAccountsStatusCheck(uint8 numberOfAccounts, bytes memory seed) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);

        address[] memory accounts = new address[](numberOfAccounts);
        address[] memory controllers = new address[](numberOfAccounts);
        for (uint i = 0; i < numberOfAccounts; i++) {
            accounts[i] = address(uint160(uint(keccak256(abi.encode(i, seed)))));
            controllers[i] = address(new Vault(cvp));
        }
        
        for (uint i = 0; i < numberOfAccounts; i++) {
            cvp.setBatchDepth(1);

            address account = accounts[i];
            address controller = controllers[i];

            vm.prank(account);
            cvp.enableController(account, controller);
            Vault(controller).setAccountStatusState(1);

            // account status check will be scheduled because checks are deferred and
            // the account status check is not ordered to be ignored or the check is not being scheduled for current onBehalfOfAccount
            cvp.setBatchDepth(2);
            cvp.setIgnoreAccountStatusCheck(true);
            cvp.setOnBehalfOfAccount(address(0));

            // even though the account status state was set to 1 which should revert,
            // it doesn't because in checks deferral we only add the accounts to the set
            // so that the checks can be performed later
            assertFalse(cvp.isAccountStatusCheckDeferred(account));
            cvp.requireAccountStatusCheck(account);
            assertTrue(cvp.isAccountStatusCheckDeferred(account));
            cvp.reset();

            // try other combinations of the conditions; account status check still being scheduled
            cvp.setBatchDepth(2);
            cvp.setIgnoreAccountStatusCheck(false);
            cvp.setOnBehalfOfAccount(account);

            assertFalse(cvp.isAccountStatusCheckDeferred(account));
            cvp.requireAccountStatusCheck(account);
            assertTrue(cvp.isAccountStatusCheckDeferred(account));
            cvp.reset();

            // account status check is no longer scheduled because
            // the account status check is ordered to be ignored and the check is being scheduled for current onBehalfOfAccount
            // because we're in a batch, the call doesn't revert but the account status check gets scheduled for later
            cvp.setBatchDepth(2);
            cvp.setIgnoreAccountStatusCheck(true);
            cvp.setOnBehalfOfAccount(account);

            assertFalse(cvp.isAccountStatusCheckDeferred(account));
            cvp.requireAccountStatusCheck(account);
            assertFalse(cvp.isAccountStatusCheckDeferred(account));
            cvp.reset();
        }

        // repeat the same test cases as above but with multiple accounts
        cvp.setBatchDepth(2);
        cvp.setIgnoreAccountStatusCheck(true);
        cvp.setOnBehalfOfAccount(address(0));

        for (uint i = 0; i < accounts.length; ++i) {assertFalse(cvp.isAccountStatusCheckDeferred(accounts[i]));}
        cvp.requireAccountsStatusCheck(accounts);
        for (uint i = 0; i < accounts.length; ++i) {assertTrue(cvp.isAccountStatusCheckDeferred(accounts[i]));}
        cvp.reset();

        cvp.setBatchDepth(2);
        cvp.setIgnoreAccountStatusCheck(false);
        cvp.setOnBehalfOfAccount(accounts[0]);

        for (uint i = 0; i < accounts.length; ++i) {assertFalse(cvp.isAccountStatusCheckDeferred(accounts[i]));}
        cvp.requireAccountsStatusCheck(accounts);
        for (uint i = 0; i < accounts.length; ++i) {assertTrue(cvp.isAccountStatusCheckDeferred(accounts[i]));}
        cvp.reset();

        cvp.setBatchDepth(2);
        cvp.setIgnoreAccountStatusCheck(true);
        cvp.setOnBehalfOfAccount(accounts[0]);

        for (uint i = 0; i < accounts.length; ++i) {assertFalse(cvp.isAccountStatusCheckDeferred(accounts[i]));}
        cvp.requireAccountsStatusCheck(accounts);
        assertFalse(cvp.isAccountStatusCheckDeferred(accounts[0]));
        for (uint i = 1; i < accounts.length; ++i) {assertTrue(cvp.isAccountStatusCheckDeferred(accounts[i]));}
        cvp.reset();

        // checks no longer deferred thus revert as all the accounts have invalid status
        cvp.setBatchDepth(1);
        cvp.setIgnoreAccountStatusCheck(true);
        cvp.setOnBehalfOfAccount(accounts[0]);

        for (uint i = 0; i < accounts.length; ++i) {assertFalse(cvp.isAccountStatusCheckDeferred(accounts[i]));}
        if (accounts.length > 1) {
            vm.expectRevert(abi.encodeWithSelector(
                CreditVaultProtocol.CVP_AccountStatusViolation.selector,
                accounts[1],
                "account status violation"
            ));
        }
        cvp.requireAccountsStatusCheck(accounts);
        if (accounts.length == 1) assertFalse(cvp.isAccountStatusCheckDeferred(accounts[0]));
    }

    function test_RequireAccountsStatusCheckUnconditional(uint8 numberOfAccounts, bytes memory seed, bool allStatusesValid) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);
        
        address[] memory accounts = new address[](numberOfAccounts);
        address[] memory controllers = new address[](numberOfAccounts);
        for (uint i = 0; i < numberOfAccounts; i++) {
            accounts[i] = address(uint160(uint(keccak256(abi.encode(i, seed)))));
            controllers[i] = address(new Vault(cvp));
        }

        uint invalidAccountsCounter;
        address[] memory invalidAccounts = new address[](numberOfAccounts);

        for (uint i = 0; i < numberOfAccounts; i++) {
            address account = accounts[i];
            address controller = controllers[i];

            vm.prank(account);
            cvp.enableController(account, controller);

            // check all the options: account state is ok, account state is violated with
            // controller returning false and reverting
            Vault(controller).setAccountStatusState(
                allStatusesValid
                ? 0
                : uint160(account) % 3 == 0
                    ? 0
                    : uint160(account) % 3 == 1
                        ? 1
                        : 2
            );

            // fist, schedule the check to be performed later to prove that after being peformed on the fly
            // account is no longer contained in the set to be performed later
            cvp.setBatchDepth(2);
            cvp.setIgnoreAccountStatusCheck(false);
            cvp.requireAccountStatusCheck(account);

            Vault(controller).clearChecks();
            cvp.clearExpectedChecks();

            // account status check will be performeded on the fly despite:
            // - checks deferral
            // - the account status check ordered to be ignored 
            // - check is being scheduled for current onBehalfOfAccount
            cvp.setBatchDepth(2);
            cvp.setIgnoreAccountStatusCheck(true);
            cvp.setOnBehalfOfAccount(account);

            assertTrue(cvp.isAccountStatusCheckDeferred(account));
            if (!(allStatusesValid || uint160(account) % 3 == 0)) {
                // for later check
                invalidAccounts[invalidAccountsCounter++] = accounts[i];

                vm.expectRevert(abi.encodeWithSelector(
                    CreditVaultProtocol.CVP_AccountStatusViolation.selector,
                    account,
                    uint160(account) % 3 == 1
                        ? bytes("account status violation")
                        : abi.encodeWithSignature("Error(string)", bytes("invalid account"))
                ));
            }
            cvp.requireAccountStatusCheckUnconditional(account);

            if (allStatusesValid || uint160(account) % 3 == 0) {
                assertFalse(cvp.isAccountStatusCheckDeferred(account));
                cvp.verifyAccountStatusChecks();
            }
        }

        // schedule the checks to be performed later to prove that after being peformed on the fly
        // accounts are no longer contained in the set to be performed later
        cvp.setBatchDepth(2);
        cvp.setIgnoreAccountStatusCheck(false);
        cvp.requireAccountsStatusCheck(accounts);

        for (uint i = 0; i < controllers.length; ++i) {Vault(controllers[i]).clearChecks();}
        cvp.clearExpectedChecks();

        cvp.setBatchDepth(2);
        cvp.setIgnoreAccountStatusCheck(true);
        cvp.setOnBehalfOfAccount(accounts[0]);

        for (uint i = 0; i < accounts.length; ++i) {assertTrue(cvp.isAccountStatusCheckDeferred(accounts[i]));}
        if (invalidAccountsCounter > 0) {
            vm.expectRevert(abi.encodeWithSelector(
                CreditVaultProtocol.CVP_AccountStatusViolation.selector,
                invalidAccounts[0],
                uint160(invalidAccounts[0]) % 3 == 1
                    ? bytes("account status violation")
                    : abi.encodeWithSignature("Error(string)", bytes("invalid account"))
            ));
        }
        cvp.requireAccountsStatusCheckUnconditional(accounts);
        assertEq(cvp.isAccountStatusCheckDeferred(accounts[0]), invalidAccountsCounter > 0);
        cvp.verifyAccountStatusChecks();
    }
}
