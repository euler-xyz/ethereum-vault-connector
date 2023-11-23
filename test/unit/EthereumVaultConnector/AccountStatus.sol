// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../evc/EthereumVaultConnectorHarness.sol";

contract AccountStatusTest is Test {
    EthereumVaultConnectorHarness internal evc;

    function setUp() public {
        evc = new EthereumVaultConnectorHarness();
    }

    function test_RequireAccountStatusCheck(
        uint8 numberOfAccounts,
        bytes memory seed,
        bool allStatusesValid
    ) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);

        for (uint256 i = 0; i < numberOfAccounts; i++) {
            address account = address(uint160(uint256(keccak256(abi.encode(i, seed)))));
            address controller = address(new Vault(evc));

            vm.prank(account);
            evc.enableController(account, controller);
            Vault(controller).clearChecks();
            evc.clearExpectedChecks();

            // check all the options: account state is ok, account state is violated with
            // controller returning false and reverting
            Vault(controller).setAccountStatusState(
                allStatusesValid ? 0 : uint160(account) % 3 == 0 ? 0 : uint160(account) % 3 == 1 ? 1 : 2
            );

            if (!(allStatusesValid || uint160(account) % 3 == 0)) {
                vm.expectRevert(
                    uint160(account) % 3 == 1 ? bytes("account status violation") : abi.encode(bytes4(uint32(2)))
                );
            }

            evc.requireAccountStatusCheck(account);

            evc.verifyAccountStatusChecks();
            Vault(controller).clearChecks();
            evc.clearExpectedChecks();
        }
    }

    function test_WhenDeferred_RequireAccountStatusCheck(uint8 numberOfAccounts, bytes memory seed) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);

        for (uint256 i = 0; i < numberOfAccounts; i++) {
            evc.setCallDepth(0);

            address account = address(uint160(uint256(keccak256(abi.encode(i, seed)))));
            address controller = address(new Vault(evc));

            vm.prank(account);
            evc.enableController(account, controller);
            Vault(controller).setAccountStatusState(1);

            // account status check will be scheduled for later due to deferred state
            evc.setCallDepth(1);

            // even though the account status state was set to 1 which should revert,
            // it doesn't because in checks deferral we only add the accounts to the set
            // so that the checks can be performed later
            assertFalse(evc.isAccountStatusCheckDeferred(account));
            evc.requireAccountStatusCheck(account);
            assertTrue(evc.isAccountStatusCheckDeferred(account));
            evc.reset();
        }
    }

    function test_RevertIfChecksReentrancy_RequireAccountStatusCheck(address account) external {
        evc.setChecksLock(true);

        vm.expectRevert(abi.encodeWithSelector(Errors.EVC_ChecksReentrancy.selector));
        evc.requireAccountStatusCheck(account);

        evc.setChecksLock(false);
        evc.requireAccountStatusCheck(account);
    }

    function test_AcquireChecksLock_RequireAccountStatusChecks(uint8 numberOfAccounts, bytes memory seed) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);

        for (uint256 i = 0; i < numberOfAccounts; i++) {
            address account = address(uint160(uint256(keccak256(abi.encode(i, seed)))));
            address controller = address(new VaultMalicious(evc));

            vm.prank(account);
            evc.enableController(account, controller);

            VaultMalicious(controller).setExpectedErrorSelector(Errors.EVC_ChecksReentrancy.selector);

            // function will revert with EVC_AccountStatusViolation according to VaultMalicious implementation
            vm.expectRevert(bytes("malicious vault"));
            evc.requireAccountStatusCheck(account);
        }
    }

    function test_RequireAccountStatusCheckNow(
        uint8 numberOfAccounts,
        bytes memory seed,
        bool allStatusesValid
    ) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);

        address[] memory accounts = new address[](numberOfAccounts);
        address[] memory controllers = new address[](numberOfAccounts);
        for (uint256 i = 0; i < numberOfAccounts; i++) {
            accounts[i] = address(uint160(uint256(keccak256(abi.encode(i, seed)))));
            controllers[i] = address(new Vault(evc));
        }

        for (uint256 i = 0; i < numberOfAccounts; i++) {
            address account = accounts[i];
            address controller = controllers[i];

            evc.setCallDepth(0);

            vm.prank(account);
            evc.enableController(account, controller);

            // check all the options: account state is ok, account state is violated with
            // controller returning false and reverting
            Vault(controller).setAccountStatusState(
                allStatusesValid ? 0 : uint160(account) % 3 == 0 ? 0 : uint160(account) % 3 == 1 ? 1 : 2
            );

            // first, schedule the check to be performed later to prove that after being performed on the fly
            // account is no longer contained in the set to be performed later
            evc.setCallDepth(1);
            evc.requireAccountStatusCheck(account);

            Vault(controller).clearChecks();
            evc.clearExpectedChecks();

            assertTrue(evc.isAccountStatusCheckDeferred(account));
            if (!(allStatusesValid || uint160(account) % 3 == 0)) {
                vm.expectRevert(
                    uint160(account) % 3 == 1 ? bytes("account status violation") : abi.encode(bytes4(uint32(2)))
                );
            }
            evc.requireAccountStatusCheckNow(account);

            if (allStatusesValid || uint160(account) % 3 == 0) {
                assertFalse(evc.isAccountStatusCheckDeferred(account));
            } else {
                assertTrue(evc.isAccountStatusCheckDeferred(account));
            }
            evc.verifyAccountStatusChecks();

            evc.reset();
        }

        // schedule the checks to be performed later to prove that after being performed on the fly
        // accounts are no longer contained in the set to be performed later
        evc.setCallDepth(1);

        for (uint256 i = 0; i < numberOfAccounts; ++i) {
            evc.requireAccountStatusCheck(accounts[i]);
            Vault(controllers[i]).clearChecks();

            assertTrue(evc.isAccountStatusCheckDeferred(accounts[i]));
        }
        evc.clearExpectedChecks();

        for (uint256 i = 0; i < numberOfAccounts; ++i) {
            address account = accounts[i];

            if (!(allStatusesValid || uint160(account) % 3 == 0)) {
                vm.expectRevert(
                    uint160(account) % 3 == 1 ? bytes("account status violation") : abi.encode(bytes4(uint32(2)))
                );
            }
            evc.requireAccountStatusCheckNow(account);

            if (allStatusesValid || uint160(account) % 3 == 0) {
                assertFalse(evc.isAccountStatusCheckDeferred(account));
            } else {
                assertTrue(evc.isAccountStatusCheckDeferred(account));
            }
        }
        evc.verifyAccountStatusChecks();
    }

    function test_RevertIfChecksReentrancy_RequireAccountStatusCheckNow(address account) external {
        evc.setChecksLock(true);

        vm.expectRevert(abi.encodeWithSelector(Errors.EVC_ChecksReentrancy.selector));
        evc.requireAccountStatusCheckNow(account);

        evc.setChecksLock(false);
        evc.requireAccountStatusCheckNow(account);
    }

    function test_AcquireChecksLock_RequireAccountStatusChecksNow(uint8 numberOfAccounts, bytes memory seed) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);

        for (uint256 i = 0; i < numberOfAccounts; i++) {
            address account = address(uint160(uint256(keccak256(abi.encode(i, seed)))));
            address controller = address(new VaultMalicious(evc));

            vm.prank(account);
            evc.enableController(account, controller);

            VaultMalicious(controller).setExpectedErrorSelector(Errors.EVC_ChecksReentrancy.selector);

            // function will revert with EVC_AccountStatusViolation according to VaultMalicious implementation
            vm.expectRevert(bytes("malicious vault"));
            evc.requireAccountStatusCheckNow(account);
        }
    }

    function test_RequireAllAccountsStatusCheckNow(
        uint8 numberOfAccounts,
        bytes memory seed,
        bool allStatusesValid
    ) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);

        address[] memory accounts = new address[](numberOfAccounts);
        address[] memory controllers = new address[](numberOfAccounts);
        for (uint256 i = 0; i < numberOfAccounts; i++) {
            accounts[i] = address(uint160(uint256(keccak256(abi.encode(i, seed)))));
            controllers[i] = address(new Vault(evc));
        }

        uint256 invalidAccountsCounter;
        address[] memory invalidAccounts = new address[](numberOfAccounts);

        for (uint256 i = 0; i < numberOfAccounts; i++) {
            address account = accounts[i];
            address controller = controllers[i];

            evc.reset();
            evc.setCallDepth(0);

            vm.prank(account);
            evc.enableController(account, controller);

            // check all the options: account state is ok, account state is violated with
            // controller returning false and reverting
            Vault(controller).setAccountStatusState(
                allStatusesValid ? 0 : uint160(account) % 3 == 0 ? 0 : uint160(account) % 3 == 1 ? 1 : 2
            );

            evc.setCallDepth(1);
            evc.requireAccountStatusCheck(account);

            Vault(controller).clearChecks();
            evc.clearExpectedChecks();

            assertTrue(evc.isAccountStatusCheckDeferred(account));
            if (!(allStatusesValid || uint160(account) % 3 == 0)) {
                // for later check
                invalidAccounts[invalidAccountsCounter++] = account;

                vm.expectRevert(
                    uint160(account) % 3 == 1 ? bytes("account status violation") : abi.encode(bytes4(uint32(2)))
                );
            }
            evc.requireAllAccountsStatusCheckNow();

            if (allStatusesValid || uint160(account) % 3 == 0) {
                assertFalse(evc.isAccountStatusCheckDeferred(account));
            } else {
                assertTrue(evc.isAccountStatusCheckDeferred(account));
            }
            evc.verifyAccountStatusChecks();
        }

        evc.reset();

        evc.setCallDepth(1);
        for (uint256 i = 0; i < accounts.length; ++i) {
            evc.requireAccountStatusCheck(accounts[i]);
        }

        for (uint256 i = 0; i < controllers.length; ++i) {
            Vault(controllers[i]).clearChecks();
        }
        evc.clearExpectedChecks();

        for (uint256 i = 0; i < accounts.length; ++i) {
            assertTrue(evc.isAccountStatusCheckDeferred(accounts[i]));
        }
        if (invalidAccountsCounter > 0) {
            vm.expectRevert(
                uint160(invalidAccounts[0]) % 3 == 1 ? bytes("account status violation") : abi.encode(bytes4(uint32(2)))
            );
        }
        evc.requireAllAccountsStatusCheckNow();
        for (uint256 i = 0; i < accounts.length; ++i) {
            assertEq(evc.isAccountStatusCheckDeferred(accounts[i]), invalidAccountsCounter > 0);
        }
        evc.verifyAccountStatusChecks();
    }

    function test_RevertIfChecksReentrancy_RequireAllAccountsStatusCheckNow(bool locked) external {
        evc.setChecksLock(locked);

        if (locked) {
            vm.expectRevert(abi.encodeWithSelector(Errors.EVC_ChecksReentrancy.selector));
        }
        evc.requireAllAccountsStatusCheckNow();
    }

    function test_AcquireChecksLock_RequireAllAccountsStatusChecksNow(
        uint8 numberOfAccounts,
        bytes memory seed
    ) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);

        address[] memory accounts = new address[](numberOfAccounts);
        address[] memory controllers = new address[](numberOfAccounts);
        for (uint256 i = 0; i < numberOfAccounts; i++) {
            accounts[i] = address(uint160(uint256(keccak256(abi.encode(i, seed)))));

            controllers[i] = address(new VaultMalicious(evc));

            vm.prank(accounts[i]);
            evc.enableController(accounts[i], controllers[i]);

            VaultMalicious(controllers[i]).setExpectedErrorSelector(Errors.EVC_ChecksReentrancy.selector);
        }

        evc.setCallDepth(1);
        for (uint256 i = 0; i < accounts.length; ++i) {
            evc.requireAccountStatusCheck(accounts[i]);
        }

        vm.expectRevert(bytes("malicious vault"));
        evc.requireAllAccountsStatusCheckNow();
    }

    function test_ForgiveAccountStatusCheck(uint8 numberOfAccounts, bytes memory seed) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);

        address[] memory accounts = new address[](numberOfAccounts);
        for (uint256 i = 0; i < numberOfAccounts; i++) {
            accounts[i] = address(uint160(uint256(keccak256(abi.encode(i, seed)))));
        }

        address controller = address(new Vault(evc));
        for (uint256 i = 0; i < numberOfAccounts; i++) {
            address account = accounts[i];

            // account status check will be scheduled for later due to deferred state
            evc.setCallDepth(1);

            vm.prank(account);
            evc.enableController(account, controller);

            assertTrue(evc.isAccountStatusCheckDeferred(account));
            vm.prank(controller);
            evc.forgiveAccountStatusCheck(account);
            assertFalse(evc.isAccountStatusCheckDeferred(account));

            evc.reset();
        }

        evc.setCallDepth(1);

        for (uint256 i = 0; i < accounts.length; ++i) {
            assertFalse(evc.isAccountStatusCheckDeferred(accounts[i]));
            evc.requireAccountStatusCheck(accounts[i]);
            assertTrue(evc.isAccountStatusCheckDeferred(accounts[i]));
        }

        for (uint256 i = 0; i < accounts.length; ++i) {
            vm.prank(controller);
            evc.forgiveAccountStatusCheck(accounts[i]);
            assertFalse(evc.isAccountStatusCheckDeferred(accounts[i]));
        }
    }

    function test_RevertIfChecksReentrancy_ForgiveAccountStatusCheckNow(address account) external {
        vm.assume(account != address(evc));

        address controller = address(new Vault(evc));

        vm.prank(account);
        evc.enableController(account, controller);

        evc.setChecksLock(true);

        vm.prank(controller);
        vm.expectRevert(abi.encodeWithSelector(Errors.EVC_ChecksReentrancy.selector));
        evc.forgiveAccountStatusCheck(account);

        evc.setChecksLock(false);
        vm.prank(controller);
        evc.forgiveAccountStatusCheck(account);
    }

    function test_RevertIfNoControllerEnabled_ForgiveAccountStatusCheck(
        uint8 numberOfAccounts,
        bytes memory seed
    ) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);

        for (uint256 i = 0; i < numberOfAccounts; i++) {
            address account = address(uint160(uint256(keccak256(abi.encode(i, seed)))));

            // account status check will be scheduled for later due to deferred state
            evc.setCallDepth(1);

            assertFalse(evc.isAccountStatusCheckDeferred(account));
            evc.requireAccountStatusCheck(account);
            assertTrue(evc.isAccountStatusCheckDeferred(account));

            // the check does not get forgiven
            vm.expectRevert(Errors.EVC_ControllerViolation.selector);
            evc.forgiveAccountStatusCheck(account);

            evc.reset();
        }
    }

    function test_RevertIfMultipleControllersEnabled_ForgiveAccountStatusCheck(
        uint8 numberOfAccounts,
        bytes memory seed
    ) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);
        address controller_1 = address(new Vault(evc));
        address controller_2 = address(new Vault(evc));

        for (uint256 i = 0; i < numberOfAccounts; i++) {
            address account = address(uint160(uint256(keccak256(abi.encode(i, seed)))));

            // account status check will be scheduled for later due to deferred state
            evc.setCallDepth(1);

            vm.prank(account);
            evc.enableController(account, controller_1);

            vm.prank(account);
            evc.enableController(account, controller_2);

            assertTrue(evc.isAccountStatusCheckDeferred(account));
            vm.prank(controller_1);
            vm.expectRevert(Errors.EVC_ControllerViolation.selector);
            evc.forgiveAccountStatusCheck(account);

            evc.reset();
        }
    }

    function test_RevertIfMsgSenderIsNotEnabledController_ForgiveAccountStatusCheck(
        uint8 numberOfAccounts,
        bytes memory seed
    ) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);

        address controller = address(new Vault(evc));
        for (uint256 i = 0; i < numberOfAccounts; i++) {
            address account = address(uint160(uint256(keccak256(abi.encode(i, seed)))));

            // account status check will be scheduled for later due to deferred state
            evc.setCallDepth(1);

            vm.prank(account);
            evc.enableController(account, controller);

            assertTrue(evc.isAccountStatusCheckDeferred(account));
            vm.prank(address(uint160(controller) + 1));
            vm.expectRevert(Errors.EVC_NotAuthorized.selector);
            evc.forgiveAccountStatusCheck(account);

            evc.reset();
        }
    }
}
