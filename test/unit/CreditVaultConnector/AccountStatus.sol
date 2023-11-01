// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../cvc/CreditVaultConnectorHarness.sol";

contract AccountStatusTest is Test {
    CreditVaultConnectorHarness internal cvc;

    function setUp() public {
        cvc = new CreditVaultConnectorHarness();
    }

    function test_RequireAccountStatusCheck(
        uint8 numberOfAccounts,
        bytes memory seed,
        bool allStatusesValid
    ) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);

        for (uint i = 0; i < numberOfAccounts; i++) {
            address account = address(
                uint160(uint(keccak256(abi.encode(i, seed))))
            );
            address controller = address(new Vault(cvc));

            vm.prank(account);
            cvc.enableController(account, controller);
            Vault(controller).clearChecks();
            cvc.clearExpectedChecks();

            // check all the options: account state is ok, account state is violated with
            // controller returning false and reverting
            Vault(controller).setAccountStatusState(
                allStatusesValid ? 0 : uint160(account) % 3 == 0
                    ? 0
                    : uint160(account) % 3 == 1
                    ? 1
                    : 2
            );

            if (!(allStatusesValid || uint160(account) % 3 == 0)) {
                vm.expectRevert(
                    uint160(account) % 3 == 1
                        ? bytes("account status violation")
                        : abi.encode(bytes4(uint32(2)))
                );
            }

            cvc.requireAccountStatusCheck(account);

            cvc.verifyAccountStatusChecks();
            Vault(controller).clearChecks();
            cvc.clearExpectedChecks();
        }
    }

    function test_WhenDeferred_RequireAccountStatusCheck(
        uint8 numberOfAccounts,
        bytes memory seed
    ) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);

        for (uint i = 0; i < numberOfAccounts; i++) {
            cvc.setCallDepth(0);

            address account = address(
                uint160(uint(keccak256(abi.encode(i, seed))))
            );
            address controller = address(new Vault(cvc));

            vm.prank(account);
            cvc.enableController(account, controller);
            Vault(controller).setAccountStatusState(1);

            // account status check will be scheduled for later due to deferred state
            cvc.setCallDepth(1);

            // even though the account status state was set to 1 which should revert,
            // it doesn't because in checks deferral we only add the accounts to the set
            // so that the checks can be performed later
            assertFalse(cvc.isAccountStatusCheckDeferred(account));
            cvc.requireAccountStatusCheck(account);
            assertTrue(cvc.isAccountStatusCheckDeferred(account));
            cvc.reset();
        }
    }

    function test_RevertIfChecksReentrancy_RequireAccountStatusCheck(
        address account
    ) external {
        cvc.setChecksLock(true);

        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            )
        );
        cvc.requireAccountStatusCheck(account);

        cvc.setChecksLock(false);
        cvc.requireAccountStatusCheck(account);
    }

    function test_AcquireChecksLock_RequireAccountStatusChecks(
        uint8 numberOfAccounts,
        bytes memory seed
    ) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);

        for (uint i = 0; i < numberOfAccounts; i++) {
            address account = address(
                uint160(uint(keccak256(abi.encode(i, seed))))
            );
            address controller = address(new VaultMalicious(cvc));

            vm.prank(account);
            cvc.enableController(account, controller);

            VaultMalicious(controller).setExpectedErrorSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            );

            // function will revert with CVC_AccountStatusViolation according to VaultMalicious implementation
            vm.expectRevert(bytes("malicious vault"));
            cvc.requireAccountStatusCheck(account);
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
        for (uint i = 0; i < numberOfAccounts; i++) {
            accounts[i] = address(
                uint160(uint(keccak256(abi.encode(i, seed))))
            );
            controllers[i] = address(new Vault(cvc));
        }

        for (uint i = 0; i < numberOfAccounts; i++) {
            address account = accounts[i];
            address controller = controllers[i];

            cvc.setCallDepth(0);

            vm.prank(account);
            cvc.enableController(account, controller);

            // check all the options: account state is ok, account state is violated with
            // controller returning false and reverting
            Vault(controller).setAccountStatusState(
                allStatusesValid ? 0 : uint160(account) % 3 == 0
                    ? 0
                    : uint160(account) % 3 == 1
                    ? 1
                    : 2
            );

            // first, schedule the check to be performed later to prove that after being peformed on the fly
            // account is no longer contained in the set to be performed later
            cvc.setCallDepth(1);
            cvc.requireAccountStatusCheck(account);

            Vault(controller).clearChecks();
            cvc.clearExpectedChecks();

            assertTrue(cvc.isAccountStatusCheckDeferred(account));
            if (!(allStatusesValid || uint160(account) % 3 == 0)) {
                vm.expectRevert(
                    uint160(account) % 3 == 1
                        ? bytes("account status violation")
                        : abi.encode(bytes4(uint32(2)))
                );
            }
            cvc.requireAccountStatusCheckNow(account);

            if (allStatusesValid || uint160(account) % 3 == 0) {
                assertFalse(cvc.isAccountStatusCheckDeferred(account));
            } else {
                assertTrue(cvc.isAccountStatusCheckDeferred(account));
            }
            cvc.verifyAccountStatusChecks();

            cvc.reset();
        }

        // schedule the checks to be performed later to prove that after being peformed on the fly
        // accounts are no longer contained in the set to be performed later
        cvc.setCallDepth(1);

        for (uint i = 0; i < numberOfAccounts; ++i) {
            cvc.requireAccountStatusCheck(accounts[i]);
            Vault(controllers[i]).clearChecks();

            assertTrue(cvc.isAccountStatusCheckDeferred(accounts[i]));
        }
        cvc.clearExpectedChecks();

        for (uint i = 0; i < numberOfAccounts; ++i) {
            address account = accounts[i];

            if (!(allStatusesValid || uint160(account) % 3 == 0)) {
                vm.expectRevert(
                    uint160(account) % 3 == 1
                        ? bytes("account status violation")
                        : abi.encode(bytes4(uint32(2)))
                );
            }
            cvc.requireAccountStatusCheckNow(account);

            if (allStatusesValid || uint160(account) % 3 == 0) {
                assertFalse(cvc.isAccountStatusCheckDeferred(account));
            } else {
                assertTrue(cvc.isAccountStatusCheckDeferred(account));
            }
        }
        cvc.verifyAccountStatusChecks();
    }

    function test_RevertIfChecksReentrancy_RequireAccountStatusCheckNow(
        address account
    ) external {
        cvc.setChecksLock(true);

        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            )
        );
        cvc.requireAccountStatusCheckNow(account);

        cvc.setChecksLock(false);
        cvc.requireAccountStatusCheckNow(account);
    }

    function test_AcquireChecksLock_RequireAccountStatusChecksNow(
        uint8 numberOfAccounts,
        bytes memory seed
    ) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);

        for (uint i = 0; i < numberOfAccounts; i++) {
            address account = address(
                uint160(uint(keccak256(abi.encode(i, seed))))
            );
            address controller = address(new VaultMalicious(cvc));

            vm.prank(account);
            cvc.enableController(account, controller);

            VaultMalicious(controller).setExpectedErrorSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            );

            // function will revert with CVC_AccountStatusViolation according to VaultMalicious implementation
            vm.expectRevert(bytes("malicious vault"));
            cvc.requireAccountStatusCheckNow(account);
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
        for (uint i = 0; i < numberOfAccounts; i++) {
            accounts[i] = address(
                uint160(uint(keccak256(abi.encode(i, seed))))
            );
            controllers[i] = address(new Vault(cvc));
        }

        uint invalidAccountsCounter;
        address[] memory invalidAccounts = new address[](numberOfAccounts);

        for (uint i = 0; i < numberOfAccounts; i++) {
            address account = accounts[i];
            address controller = controllers[i];

            cvc.reset();
            cvc.setCallDepth(0);

            vm.prank(account);
            cvc.enableController(account, controller);

            // check all the options: account state is ok, account state is violated with
            // controller returning false and reverting
            Vault(controller).setAccountStatusState(
                allStatusesValid ? 0 : uint160(account) % 3 == 0
                    ? 0
                    : uint160(account) % 3 == 1
                    ? 1
                    : 2
            );

            cvc.setCallDepth(1);
            cvc.requireAccountStatusCheck(account);

            Vault(controller).clearChecks();
            cvc.clearExpectedChecks();

            assertTrue(cvc.isAccountStatusCheckDeferred(account));
            if (!(allStatusesValid || uint160(account) % 3 == 0)) {
                // for later check
                invalidAccounts[invalidAccountsCounter++] = account;

                vm.expectRevert(
                    uint160(account) % 3 == 1
                        ? bytes("account status violation")
                        : abi.encode(bytes4(uint32(2)))
                );
            }
            cvc.requireAllAccountsStatusCheckNow();

            if (allStatusesValid || uint160(account) % 3 == 0) {
                assertFalse(cvc.isAccountStatusCheckDeferred(account));
            } else {
                assertTrue(cvc.isAccountStatusCheckDeferred(account));
            }
            cvc.verifyAccountStatusChecks();
        }

        cvc.reset();

        cvc.setCallDepth(1);
        for (uint i = 0; i < accounts.length; ++i) {
            cvc.requireAccountStatusCheck(accounts[i]);
        }

        for (uint i = 0; i < controllers.length; ++i) {
            Vault(controllers[i]).clearChecks();
        }
        cvc.clearExpectedChecks();

        for (uint i = 0; i < accounts.length; ++i) {
            assertTrue(cvc.isAccountStatusCheckDeferred(accounts[i]));
        }
        if (invalidAccountsCounter > 0) {
            vm.expectRevert(
                uint160(invalidAccounts[0]) % 3 == 1
                    ? bytes("account status violation")
                    : abi.encode(bytes4(uint32(2)))
            );
        }
        cvc.requireAllAccountsStatusCheckNow();
        for (uint i = 0; i < accounts.length; ++i) {
            assertEq(
                cvc.isAccountStatusCheckDeferred(accounts[i]),
                invalidAccountsCounter > 0
            );
        }
        cvc.verifyAccountStatusChecks();
    }

    function test_RevertIfChecksReentrancy_RequireAllAccountsStatusCheckNow(
        bool locked
    ) external {
        cvc.setChecksLock(locked);

        if (locked)
            vm.expectRevert(
                abi.encodeWithSelector(
                    CreditVaultConnector.CVC_ChecksReentrancy.selector
                )
            );
        cvc.requireAllAccountsStatusCheckNow();
    }

    function test_AcquireChecksLock_RequireAllAccountsStatusChecksNow(
        uint8 numberOfAccounts,
        bytes memory seed
    ) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);

        address[] memory accounts = new address[](numberOfAccounts);
        address[] memory controllers = new address[](numberOfAccounts);
        for (uint i = 0; i < numberOfAccounts; i++) {
            accounts[i] = address(
                uint160(uint(keccak256(abi.encode(i, seed))))
            );

            controllers[i] = address(new VaultMalicious(cvc));

            vm.prank(accounts[i]);
            cvc.enableController(accounts[i], controllers[i]);

            VaultMalicious(controllers[i]).setExpectedErrorSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            );
        }

        cvc.setCallDepth(1);
        for (uint i = 0; i < accounts.length; ++i) {
            cvc.requireAccountStatusCheck(accounts[i]);
        }

        vm.expectRevert(bytes("malicious vault"));
        cvc.requireAllAccountsStatusCheckNow();
    }

    function test_ForgiveAccountStatusCheck(
        uint8 numberOfAccounts,
        bytes memory seed
    ) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);

        address[] memory accounts = new address[](numberOfAccounts);
        for (uint i = 0; i < numberOfAccounts; i++) {
            accounts[i] = address(
                uint160(uint(keccak256(abi.encode(i, seed))))
            );
        }

        address controller = address(new Vault(cvc));
        for (uint i = 0; i < numberOfAccounts; i++) {
            address account = accounts[i];

            // account status check will be scheduled for later due to deferred state
            cvc.setCallDepth(1);

            vm.prank(account);
            cvc.enableController(account, controller);

            assertTrue(cvc.isAccountStatusCheckDeferred(account));
            vm.prank(controller);
            cvc.forgiveAccountStatusCheck(account);
            assertFalse(cvc.isAccountStatusCheckDeferred(account));

            cvc.reset();
        }

        cvc.setCallDepth(1);

        for (uint i = 0; i < accounts.length; ++i) {
            assertFalse(cvc.isAccountStatusCheckDeferred(accounts[i]));
            cvc.requireAccountStatusCheck(accounts[i]);
            assertTrue(cvc.isAccountStatusCheckDeferred(accounts[i]));
        }

        for (uint i = 0; i < accounts.length; ++i) {
            vm.prank(controller);
            cvc.forgiveAccountStatusCheck(accounts[i]);
            assertFalse(cvc.isAccountStatusCheckDeferred(accounts[i]));
        }
    }

    function test_RevertIfChecksReentrancy_ForgiveAccountStatusCheckNow(
        address account
    ) external {
        address controller = address(new Vault(cvc));

        vm.prank(account);
        cvc.enableController(account, controller);

        cvc.setChecksLock(true);

        vm.prank(controller);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            )
        );
        cvc.forgiveAccountStatusCheck(account);

        cvc.setChecksLock(false);
        vm.prank(controller);
        cvc.forgiveAccountStatusCheck(account);
    }

    function test_RevertIfNoControllerEnabled_ForgiveAccountStatusCheck(
        uint8 numberOfAccounts,
        bytes memory seed
    ) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);

        for (uint i = 0; i < numberOfAccounts; i++) {
            address account = address(
                uint160(uint(keccak256(abi.encode(i, seed))))
            );

            // account status check will be scheduled for later due to deferred state
            cvc.setCallDepth(1);

            assertFalse(cvc.isAccountStatusCheckDeferred(account));
            cvc.requireAccountStatusCheck(account);
            assertTrue(cvc.isAccountStatusCheckDeferred(account));

            // the check does not get forgiven
            vm.expectRevert(
                CreditVaultConnector.CVC_ControllerViolation.selector
            );
            cvc.forgiveAccountStatusCheck(account);

            cvc.reset();
        }
    }

    function test_RevertIfMultipleControllersEnabled_ForgiveAccountStatusCheck(
        uint8 numberOfAccounts,
        bytes memory seed
    ) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);
        address controller_1 = address(new Vault(cvc));
        address controller_2 = address(new Vault(cvc));

        for (uint i = 0; i < numberOfAccounts; i++) {
            address account = address(
                uint160(uint(keccak256(abi.encode(i, seed))))
            );

            // account status check will be scheduled for later due to deferred state
            cvc.setCallDepth(1);

            vm.prank(account);
            cvc.enableController(account, controller_1);

            vm.prank(account);
            cvc.enableController(account, controller_2);

            assertTrue(cvc.isAccountStatusCheckDeferred(account));
            vm.prank(controller_1);
            vm.expectRevert(
                CreditVaultConnector.CVC_ControllerViolation.selector
            );
            cvc.forgiveAccountStatusCheck(account);

            cvc.reset();
        }
    }

    function test_RevertIfMsgSenderIsNotEnabledController_ForgiveAccountStatusCheck(
        uint8 numberOfAccounts,
        bytes memory seed
    ) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);

        address controller = address(new Vault(cvc));
        for (uint i = 0; i < numberOfAccounts; i++) {
            address account = address(
                uint160(uint(keccak256(abi.encode(i, seed))))
            );

            // account status check will be scheduled for later due to deferred state
            cvc.setCallDepth(1);

            vm.prank(account);
            cvc.enableController(account, controller);

            assertTrue(cvc.isAccountStatusCheckDeferred(account));
            vm.prank(address(uint160(controller) + 1));
            vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
            cvc.forgiveAccountStatusCheck(account);

            cvc.reset();
        }
    }
}
