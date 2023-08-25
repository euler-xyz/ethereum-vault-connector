// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../../utils/CreditVaultConnectorHarness.sol";

contract AccountStatusTest is Test {
    CreditVaultConnectorHarness internal cvc;

    function setUp() public {
        cvc = new CreditVaultConnectorHarness();
    }

    function test_CheckAccountsStatus(
        address[] memory accounts,
        bool allStatusesValid
    ) external {
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

            address controller = address(new Vault(cvc));

            address owner = cvc.getAccountOwnerNoRevert(account);
            vm.prank(owner == address(0) ? account : owner);
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

            if (!(allStatusesValid || uint160(account) % 3 == 0)) {
                assertFalse(cvc.checkAccountStatus(account));
            } else {
                assertTrue(cvc.checkAccountStatus(account));
            }
        }

        bool[] memory isValid = cvc.checkAccountsStatus(accounts);
        for (uint i = 0; i < accounts.length; i++) {
            address account = accounts[i];

            if (!(allStatusesValid || uint160(account) % 3 == 0))
                assertFalse(isValid[i]);
            else assertTrue(isValid[i]);
        }
    }

    function test_RevertIfChecksReentrancy_CheckAccountsStatus(
        uint8 index,
        address[] calldata accounts
    ) external {
        vm.assume(index < accounts.length);
        vm.assume(accounts.length > 0 && accounts.length <= Set.MAX_ELEMENTS);

        cvc.setChecksLock(true);

        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            )
        );
        cvc.checkAccountStatus(accounts[index]);

        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            )
        );
        cvc.checkAccountsStatus(accounts);

        cvc.setChecksLock(false);
        cvc.checkAccountStatus(accounts[index]);
        cvc.checkAccountsStatus(accounts);
    }

    function test_AcquireChecksLock_CheckAccountsStatus(
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

            // function will return false because malicious vault encounter CVC_ChecksReentrancy error
            assertFalse(cvc.checkAccountStatus(accounts[i]));
        }

        bool[] memory result = cvc.checkAccountsStatus(accounts);
        for (uint i; i < result.length; ++i) {
            assertFalse(result[i]);
        }
    }

    function test_RequireAccountsStatusCheck(
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
                // for later checks
                invalidAccounts[invalidAccountsCounter++] = accounts[i];

                vm.expectRevert(
                    abi.encodeWithSelector(
                        CreditVaultConnector
                            .CVC_AccountStatusViolation
                            .selector,
                        account,
                        uint160(account) % 3 == 1
                            ? bytes("account status violation")
                            : abi.encodeWithSignature(
                                "Error(string)",
                                bytes("invalid account")
                            )
                    )
                );
            }

            cvc.requireAccountStatusCheck(account);

            cvc.verifyAccountStatusChecks();
            Vault(controller).clearChecks();
            cvc.clearExpectedChecks();
        }

        // if there's any account which is not valid, the whole transaction should revert
        if (invalidAccountsCounter > 0) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    CreditVaultConnector.CVC_AccountStatusViolation.selector,
                    invalidAccounts[0],
                    uint160(invalidAccounts[0]) % 3 == 1
                        ? bytes("account status violation")
                        : abi.encodeWithSignature(
                            "Error(string)",
                            bytes("invalid account")
                        )
                )
            );
        }

        cvc.requireAccountsStatusCheck(accounts);
        cvc.verifyAccountStatusChecks();
    }

    function test_WhenDeferred_RequireAccountsStatusCheck(
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
            controllers[i] = address(new Vault(cvc));
        }

        for (uint i = 0; i < numberOfAccounts; i++) {
            cvc.setBatchDepth(0);

            address account = accounts[i];
            address controller = controllers[i];

            vm.prank(account);
            cvc.enableController(account, controller);
            Vault(controller).setAccountStatusState(1);

            // account status check will be scheduled for later due to deferred state
            cvc.setBatchDepth(1);

            // even though the account status state was set to 1 which should revert,
            // it doesn't because in checks deferral we only add the accounts to the set
            // so that the checks can be performed later
            assertFalse(cvc.isAccountStatusCheckDeferred(account));
            cvc.requireAccountStatusCheck(account);
            assertTrue(cvc.isAccountStatusCheckDeferred(account));
            cvc.reset();
        }

        cvc.setBatchDepth(1);

        for (uint i = 0; i < accounts.length; ++i) {
            assertFalse(cvc.isAccountStatusCheckDeferred(accounts[i]));
        }
        cvc.requireAccountsStatusCheck(accounts);
        for (uint i = 0; i < accounts.length; ++i) {
            assertTrue(cvc.isAccountStatusCheckDeferred(accounts[i]));
        }
        cvc.reset();

        // another test case
        // checks no longer deferred thus revert as all the accounts have invalid status
        cvc.setBatchDepth(0);

        for (uint i = 0; i < accounts.length; ++i) {
            assertFalse(cvc.isAccountStatusCheckDeferred(accounts[i]));
        }
        if (accounts.length > 0) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    CreditVaultConnector.CVC_AccountStatusViolation.selector,
                    accounts[0],
                    "account status violation"
                )
            );
        }
        cvc.requireAccountsStatusCheck(accounts);
    }

    function test_RevertIfChecksReentrancy_RequireAccountsStatusCheck(
        uint8 index,
        address[] calldata accounts
    ) external {
        vm.assume(index < accounts.length);
        vm.assume(accounts.length > 0 && accounts.length <= Set.MAX_ELEMENTS);

        cvc.setChecksLock(true);

        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            )
        );
        cvc.requireAccountStatusCheck(accounts[index]);

        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            )
        );
        cvc.requireAccountsStatusCheck(accounts);

        cvc.setChecksLock(false);
        cvc.requireAccountStatusCheck(accounts[index]);
        cvc.requireAccountsStatusCheck(accounts);
    }

    function test_AcquireChecksLock_RequireAccountsStatusChecks(
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

            // function will revert with CVC_AccountStatusViolation according to VaultMalicious implementation
            vm.expectRevert(
                abi.encodeWithSelector(
                    CreditVaultConnector.CVC_AccountStatusViolation.selector,
                    accounts[i],
                    "malicious vault"
                )
            );
            cvc.requireAccountStatusCheck(accounts[i]);
        }

        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_AccountStatusViolation.selector,
                accounts[0],
                "malicious vault"
            )
        );
        cvc.requireAccountsStatusCheck(accounts);
    }

    function test_RequireAccountsStatusCheckNow(
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

            cvc.setBatchDepth(0);

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
            cvc.setBatchDepth(1);
            cvc.requireAccountStatusCheck(account);

            Vault(controller).clearChecks();
            cvc.clearExpectedChecks();

            assertTrue(cvc.isAccountStatusCheckDeferred(account));
            if (!(allStatusesValid || uint160(account) % 3 == 0)) {
                // for later check
                invalidAccounts[invalidAccountsCounter++] = account;

                vm.expectRevert(
                    abi.encodeWithSelector(
                        CreditVaultConnector
                            .CVC_AccountStatusViolation
                            .selector,
                        account,
                        uint160(account) % 3 == 1
                            ? bytes("account status violation")
                            : abi.encodeWithSignature(
                                "Error(string)",
                                bytes("invalid account")
                            )
                    )
                );
            }
            cvc.requireAccountStatusCheckNow(account);

            if (allStatusesValid || uint160(account) % 3 == 0) {
                assertFalse(cvc.isAccountStatusCheckDeferred(account));
            } else {
                assertTrue(cvc.isAccountStatusCheckDeferred(account));
            }
            cvc.verifyAccountStatusChecks();
        }

        // schedule the checks to be performed later to prove that after being peformed on the fly
        // accounts are no longer contained in the set to be performed later
        cvc.setBatchDepth(1);
        cvc.requireAccountsStatusCheck(accounts);

        for (uint i = 0; i < controllers.length; ++i) {
            Vault(controllers[i]).clearChecks();
        }
        cvc.clearExpectedChecks();

        for (uint i = 0; i < accounts.length; ++i) {
            assertTrue(cvc.isAccountStatusCheckDeferred(accounts[i]));
        }
        if (invalidAccountsCounter > 0) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    CreditVaultConnector.CVC_AccountStatusViolation.selector,
                    invalidAccounts[0],
                    uint160(invalidAccounts[0]) % 3 == 1
                        ? bytes("account status violation")
                        : abi.encodeWithSignature(
                            "Error(string)",
                            bytes("invalid account")
                        )
                )
            );
        }
        cvc.requireAccountsStatusCheckNow(accounts);
        for (uint i = 0; i < accounts.length; ++i) {
            assertEq(
                cvc.isAccountStatusCheckDeferred(accounts[i]),
                invalidAccountsCounter > 0
            );
        }
        cvc.verifyAccountStatusChecks();
    }

    function test_RevertIfChecksReentrancy_RequireAccountsStatusCheckNow(
        uint8 index,
        address[] calldata accounts
    ) external {
        vm.assume(index < accounts.length);
        vm.assume(accounts.length > 0 && accounts.length <= Set.MAX_ELEMENTS);

        cvc.setChecksLock(true);

        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            )
        );
        cvc.requireAccountStatusCheckNow(accounts[index]);

        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            )
        );
        cvc.requireAccountsStatusCheckNow(accounts);

        cvc.setChecksLock(false);
        cvc.requireAccountStatusCheckNow(accounts[index]);
        cvc.requireAccountsStatusCheckNow(accounts);
    }

    function test_AcquireChecksLock_RequireAccountsStatusChecksNow(
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

            // function will revert with CVC_AccountStatusViolation according to VaultMalicious implementation
            vm.expectRevert(
                abi.encodeWithSelector(
                    CreditVaultConnector.CVC_AccountStatusViolation.selector,
                    accounts[i],
                    "malicious vault"
                )
            );
            cvc.requireAccountStatusCheckNow(accounts[i]);
        }

        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_AccountStatusViolation.selector,
                accounts[0],
                "malicious vault"
            )
        );
        cvc.requireAccountsStatusCheckNow(accounts);
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
            cvc.setBatchDepth(0);

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

            cvc.setBatchDepth(1);
            cvc.requireAccountStatusCheck(account);

            Vault(controller).clearChecks();
            cvc.clearExpectedChecks();

            assertTrue(cvc.isAccountStatusCheckDeferred(account));
            if (!(allStatusesValid || uint160(account) % 3 == 0)) {
                // for later check
                invalidAccounts[invalidAccountsCounter++] = account;

                vm.expectRevert(
                    abi.encodeWithSelector(
                        CreditVaultConnector
                            .CVC_AccountStatusViolation
                            .selector,
                        account,
                        uint160(account) % 3 == 1
                            ? bytes("account status violation")
                            : abi.encodeWithSignature(
                                "Error(string)",
                                bytes("invalid account")
                            )
                    )
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

        cvc.setBatchDepth(1);
        cvc.requireAccountsStatusCheck(accounts);

        for (uint i = 0; i < controllers.length; ++i) {
            Vault(controllers[i]).clearChecks();
        }
        cvc.clearExpectedChecks();

        for (uint i = 0; i < accounts.length; ++i) {
            assertTrue(cvc.isAccountStatusCheckDeferred(accounts[i]));
        }
        if (invalidAccountsCounter > 0) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    CreditVaultConnector.CVC_AccountStatusViolation.selector,
                    invalidAccounts[0],
                    uint160(invalidAccounts[0]) % 3 == 1
                        ? bytes("account status violation")
                        : abi.encodeWithSignature(
                            "Error(string)",
                            bytes("invalid account")
                        )
                )
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

        cvc.setBatchDepth(1);
        cvc.requireAccountsStatusCheck(accounts);

        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_AccountStatusViolation.selector,
                accounts[0],
                "malicious vault"
            )
        );
        cvc.requireAllAccountsStatusCheckNow();
    }

    function test_ForgiveAccountsStatusCheck(
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
            cvc.setBatchDepth(1);

            vm.prank(account);
            cvc.enableController(account, controller);

            assertTrue(cvc.isAccountStatusCheckDeferred(account));
            vm.prank(controller);
            cvc.forgiveAccountStatusCheck(account);
            assertFalse(cvc.isAccountStatusCheckDeferred(account));

            cvc.reset();
        }

        cvc.setBatchDepth(1);

        for (uint i = 0; i < accounts.length; ++i) {
            assertFalse(cvc.isAccountStatusCheckDeferred(accounts[i]));
        }
        cvc.requireAccountsStatusCheck(accounts);
        for (uint i = 0; i < accounts.length; ++i) {
            assertTrue(cvc.isAccountStatusCheckDeferred(accounts[i]));
        }

        vm.prank(controller);
        cvc.forgiveAccountsStatusCheck(accounts);
        for (uint i = 0; i < accounts.length; ++i) {
            assertFalse(cvc.isAccountStatusCheckDeferred(accounts[i]));
        }
    }

    function test_RevertIfChecksReentrancy_ForgiveAccountsStatusCheckNow(
        uint8 index,
        uint8 numberOfAccounts,
        uint seed
    ) external {
        vm.assume(index < numberOfAccounts);
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);

        address controller = address(new Vault(cvc));
        address[] memory accounts = new address[](numberOfAccounts);
        for (uint i = 0; i < numberOfAccounts; i++) {
            accounts[i] = address(
                uint160(uint(keccak256(abi.encode(i, seed))))
            );

            vm.prank(accounts[i]);
            cvc.enableController(accounts[i], controller);
        }

        cvc.setChecksLock(true);

        vm.prank(controller);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            )
        );
        cvc.forgiveAccountStatusCheck(accounts[index]);

        vm.prank(controller);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            )
        );
        cvc.forgiveAccountsStatusCheck(accounts);

        cvc.setChecksLock(false);
        vm.prank(controller);
        cvc.forgiveAccountStatusCheck(accounts[index]);
        vm.prank(controller);
        cvc.forgiveAccountsStatusCheck(accounts);
    }

    function test_RevertIfNoControllerEnabled_ForgiveAccountsStatusCheck(
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

        for (uint i = 0; i < numberOfAccounts; i++) {
            address account = accounts[i];

            // account status check will be scheduled for later due to deferred state
            cvc.setBatchDepth(1);

            assertFalse(cvc.isAccountStatusCheckDeferred(account));
            cvc.requireAccountsStatusCheck(accounts);
            assertTrue(cvc.isAccountStatusCheckDeferred(account));

            // the check does not get forgiven
            vm.expectRevert(
                CreditVaultConnector.CVC_ControllerViolation.selector
            );
            cvc.forgiveAccountStatusCheck(account);

            cvc.reset();
        }

        cvc.setBatchDepth(1);

        for (uint i = 0; i < accounts.length; ++i) {
            assertFalse(cvc.isAccountStatusCheckDeferred(accounts[i]));
        }
        cvc.requireAccountsStatusCheck(accounts);
        for (uint i = 0; i < accounts.length; ++i) {
            assertTrue(cvc.isAccountStatusCheckDeferred(accounts[i]));
        }

        // the checks do not get forgiven
        vm.expectRevert(CreditVaultConnector.CVC_ControllerViolation.selector);
        cvc.forgiveAccountsStatusCheck(accounts);
    }

    function test_RevertIfMultipleControllersEnabled_ForgiveAccountsStatusCheck(
        uint8 numberOfAccounts,
        bytes memory seed
    ) external {
        vm.assume(numberOfAccounts > 0 && numberOfAccounts <= Set.MAX_ELEMENTS);
        vm.assume(uint256(bytes32(seed)) > numberOfAccounts);

        address[] memory accounts = new address[](numberOfAccounts);
        for (uint i = 0; i < numberOfAccounts; i++) {
            accounts[i] = address(
                uint160(uint(keccak256(abi.encode(i, seed))))
            );
        }

        address controller_1 = address(new Vault(cvc));
        address controller_2 = address(new Vault(cvc));
        for (uint i = 0; i < numberOfAccounts; i++) {
            address account = accounts[i];

            // account status check will be scheduled for later due to deferred state
            cvc.setBatchDepth(1);

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

        cvc.setBatchDepth(1);

        for (uint i = 0; i < accounts.length; ++i) {
            assertFalse(cvc.isAccountStatusCheckDeferred(accounts[i]));
        }
        cvc.requireAccountsStatusCheck(accounts);
        for (uint i = 0; i < accounts.length; ++i) {
            assertTrue(cvc.isAccountStatusCheckDeferred(accounts[i]));
        }

        vm.prank(controller_1);
        vm.expectRevert(CreditVaultConnector.CVC_ControllerViolation.selector);
        cvc.forgiveAccountsStatusCheck(accounts);

        // leave only one account with multiple controllers enabled
        for (uint i = 0; i < accounts.length; i++) {
            if (uint256(bytes32(seed)) % accounts.length == i) continue;
            Vault(controller_2).disableController(accounts[i]);
        }

        // still reverts
        vm.prank(controller_1);
        vm.expectRevert(CreditVaultConnector.CVC_ControllerViolation.selector);
        cvc.forgiveAccountsStatusCheck(accounts);
    }

    function test_RevertIfMsgSenderIsNotEnabledController_ForgiveAccountsStatusCheck(
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
            cvc.setBatchDepth(1);

            vm.prank(account);
            cvc.enableController(account, controller);

            assertTrue(cvc.isAccountStatusCheckDeferred(account));
            vm.prank(address(uint160(controller) + 1));
            vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
            cvc.forgiveAccountStatusCheck(account);

            cvc.reset();
        }

        cvc.setBatchDepth(1);

        for (uint i = 0; i < accounts.length; ++i) {
            assertFalse(cvc.isAccountStatusCheckDeferred(accounts[i]));
        }
        cvc.requireAccountsStatusCheck(accounts);
        for (uint i = 0; i < accounts.length; ++i) {
            assertTrue(cvc.isAccountStatusCheckDeferred(accounts[i]));
        }

        vm.prank(address(uint160(controller) - 1));
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.forgiveAccountsStatusCheck(accounts);
    }
}
