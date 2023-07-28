// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../../utils/CreditVaultProtocolHarnessed.sol";

contract AccountStatusTest is Test {
    CreditVaultProtocolHarnessed internal cvp;

    function setUp() public {
        cvp = new CreditVaultProtocolHarnessed();
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

            address controller = address(new Vault(cvp));

            vm.prank(account);
            cvp.enableController(account, controller);

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
                assertFalse(cvp.checkAccountStatus(account));
            } else {
                assertTrue(cvp.checkAccountStatus(account));
            }
        }

        bool[] memory isValid = cvp.checkAccountsStatus(accounts);
        for (uint i = 0; i < accounts.length; i++) {
            address account = accounts[i];

            if (!(allStatusesValid || uint160(account) % 3 == 0))
                assertFalse(isValid[i]);
            else assertTrue(isValid[i]);
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
                        CreditVaultProtocol.CVP_AccountStatusViolation.selector,
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

            cvp.requireAccountStatusCheck(account);

            if (allStatusesValid || uint160(account) % 3 == 0)
                cvp.verifyAccountStatusChecks();

            Vault(controller).clearChecks();
            cvp.clearExpectedChecks();
        }

        // if there's any account which is not valid, the whole transaction should revert
        if (invalidAccountsCounter > 0) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    CreditVaultProtocol.CVP_AccountStatusViolation.selector,
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

        cvp.requireAccountsStatusCheck(accounts);
        cvp.verifyAccountStatusChecks();
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
            controllers[i] = address(new Vault(cvp));
        }

        for (uint i = 0; i < numberOfAccounts; i++) {
            cvp.setBatchDepth(0);

            address account = accounts[i];
            address controller = controllers[i];

            vm.prank(account);
            cvp.enableController(account, controller);
            Vault(controller).setAccountStatusState(1);

            // account status check will be scheduled for later due to deferred state
            cvp.setBatchDepth(1);

            // even though the account status state was set to 1 which should revert,
            // it doesn't because in checks deferral we only add the accounts to the set
            // so that the checks can be performed later
            assertFalse(cvp.isAccountStatusCheckDeferred(account));
            cvp.requireAccountStatusCheck(account);
            assertTrue(cvp.isAccountStatusCheckDeferred(account));
            cvp.reset();
        }

        cvp.setBatchDepth(1);

        for (uint i = 0; i < accounts.length; ++i) {
            assertFalse(cvp.isAccountStatusCheckDeferred(accounts[i]));
        }
        cvp.requireAccountsStatusCheck(accounts);
        for (uint i = 0; i < accounts.length; ++i) {
            assertTrue(cvp.isAccountStatusCheckDeferred(accounts[i]));
        }
        cvp.reset();

        // another test case
        // checks no longer deferred thus revert as all the accounts have invalid status
        cvp.setBatchDepth(0);

        for (uint i = 0; i < accounts.length; ++i) {
            assertFalse(cvp.isAccountStatusCheckDeferred(accounts[i]));
        }
        if (accounts.length > 0) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    CreditVaultProtocol.CVP_AccountStatusViolation.selector,
                    accounts[0],
                    "account status violation"
                )
            );
        }
        cvp.requireAccountsStatusCheck(accounts);
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
                allStatusesValid ? 0 : uint160(account) % 3 == 0
                    ? 0
                    : uint160(account) % 3 == 1
                    ? 1
                    : 2
            );

            // fist, schedule the check to be performed later to prove that after being peformed on the fly
            // account is no longer contained in the set to be performed later
            cvp.setBatchDepth(1);
            cvp.requireAccountStatusCheck(account);

            Vault(controller).clearChecks();
            cvp.clearExpectedChecks();

            // account status check will be performeded on the fly despite checks deferral
            cvp.setBatchDepth(1);

            assertTrue(cvp.isAccountStatusCheckDeferred(account));
            if (!(allStatusesValid || uint160(account) % 3 == 0)) {
                // for later check
                invalidAccounts[invalidAccountsCounter++] = accounts[i];

                vm.expectRevert(
                    abi.encodeWithSelector(
                        CreditVaultProtocol.CVP_AccountStatusViolation.selector,
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
            cvp.requireAccountStatusCheckNow(account);

            if (allStatusesValid || uint160(account) % 3 == 0) {
                assertFalse(cvp.isAccountStatusCheckDeferred(account));
                cvp.verifyAccountStatusChecks();
            }
        }

        // schedule the checks to be performed later to prove that after being peformed on the fly
        // accounts are no longer contained in the set to be performed later
        cvp.setBatchDepth(1);
        cvp.requireAccountsStatusCheck(accounts);

        for (uint i = 0; i < controllers.length; ++i) {
            Vault(controllers[i]).clearChecks();
        }
        cvp.clearExpectedChecks();

        cvp.setBatchDepth(1);

        for (uint i = 0; i < accounts.length; ++i) {
            assertTrue(cvp.isAccountStatusCheckDeferred(accounts[i]));
        }
        if (invalidAccountsCounter > 0) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    CreditVaultProtocol.CVP_AccountStatusViolation.selector,
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
        cvp.requireAccountsStatusCheckNow(accounts);
        assertEq(
            cvp.isAccountStatusCheckDeferred(accounts[0]),
            invalidAccountsCounter > 0
        );
        cvp.verifyAccountStatusChecks();
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

        address controller = address(new Vault(cvp));
        for (uint i = 0; i < numberOfAccounts; i++) {
            address account = accounts[i];

            // account status check will be scheduled for later due to deferred state
            cvp.setBatchDepth(1);

            vm.prank(account);
            cvp.enableController(account, controller);

            assertTrue(cvp.isAccountStatusCheckDeferred(account));
            vm.prank(controller);
            cvp.forgiveAccountStatusCheck(account);
            assertFalse(cvp.isAccountStatusCheckDeferred(account));

            cvp.reset();
        }

        cvp.setBatchDepth(1);

        for (uint i = 0; i < accounts.length; ++i) {
            assertFalse(cvp.isAccountStatusCheckDeferred(accounts[i]));
        }
        cvp.requireAccountsStatusCheck(accounts);
        for (uint i = 0; i < accounts.length; ++i) {
            assertTrue(cvp.isAccountStatusCheckDeferred(accounts[i]));
        }

        vm.prank(controller);
        cvp.forgiveAccountsStatusCheck(accounts);
        for (uint i = 0; i < accounts.length; ++i) {
            assertFalse(cvp.isAccountStatusCheckDeferred(accounts[i]));
        }
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
            cvp.setBatchDepth(1);

            assertFalse(cvp.isAccountStatusCheckDeferred(account));
            cvp.requireAccountsStatusCheck(accounts);
            assertTrue(cvp.isAccountStatusCheckDeferred(account));

            // the check does not get forgiven
            vm.expectRevert(CreditVaultProtocol.CVP_ControllerViolation.selector);
            cvp.forgiveAccountStatusCheck(account);

            cvp.reset();
        }

        cvp.setBatchDepth(1);

        for (uint i = 0; i < accounts.length; ++i) {
            assertFalse(cvp.isAccountStatusCheckDeferred(accounts[i]));
        }
        cvp.requireAccountsStatusCheck(accounts);
        for (uint i = 0; i < accounts.length; ++i) {
            assertTrue(cvp.isAccountStatusCheckDeferred(accounts[i]));
        }

        // the checks do not get forgiven
        vm.expectRevert(CreditVaultProtocol.CVP_ControllerViolation.selector);
        cvp.forgiveAccountsStatusCheck(accounts);
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

        address controller_1 = address(new Vault(cvp));
        address controller_2 = address(new Vault(cvp));
        for (uint i = 0; i < numberOfAccounts; i++) {
            address account = accounts[i];

            // account status check will be scheduled for later due to deferred state
            cvp.setBatchDepth(1);

            vm.prank(account);
            cvp.enableController(account, controller_1);

            vm.prank(account);
            cvp.enableController(account, controller_2);

            assertTrue(cvp.isAccountStatusCheckDeferred(account));
            vm.prank(controller_1);
            vm.expectRevert(CreditVaultProtocol.CVP_ControllerViolation.selector);
            cvp.forgiveAccountStatusCheck(account);

            cvp.reset();
        }

        cvp.setBatchDepth(1);

        for (uint i = 0; i < accounts.length; ++i) {
            assertFalse(cvp.isAccountStatusCheckDeferred(accounts[i]));
        }
        cvp.requireAccountsStatusCheck(accounts);
        for (uint i = 0; i < accounts.length; ++i) {
            assertTrue(cvp.isAccountStatusCheckDeferred(accounts[i]));
        }

        vm.prank(controller_1);
        vm.expectRevert(CreditVaultProtocol.CVP_ControllerViolation.selector);
        cvp.forgiveAccountsStatusCheck(accounts);

        // leave only one account with multiple controllers enabled
        for (uint i = 0; i < accounts.length; i++) {
            if (uint256(bytes32(seed)) % accounts.length == i) continue; 
            Vault(controller_2).disableController(accounts[i]);
        }

        // still reverts
        vm.prank(controller_1);
        vm.expectRevert(CreditVaultProtocol.CVP_ControllerViolation.selector);
        cvp.forgiveAccountsStatusCheck(accounts);
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

        address controller = address(new Vault(cvp));
        for (uint i = 0; i < numberOfAccounts; i++) {
            address account = accounts[i];

            // account status check will be scheduled for later due to deferred state
            cvp.setBatchDepth(1);

            vm.prank(account);
            cvp.enableController(account, controller);

            assertTrue(cvp.isAccountStatusCheckDeferred(account));
            vm.prank(address(uint160(controller) + 1));
            vm.expectRevert(CreditVaultProtocol.CVP_NotAuthorized.selector);
            cvp.forgiveAccountStatusCheck(account);

            cvp.reset();
        }

        cvp.setBatchDepth(1);

        for (uint i = 0; i < accounts.length; ++i) {
            assertFalse(cvp.isAccountStatusCheckDeferred(accounts[i]));
        }
        cvp.requireAccountsStatusCheck(accounts);
        for (uint i = 0; i < accounts.length; ++i) {
            assertTrue(cvp.isAccountStatusCheckDeferred(accounts[i]));
        }

        vm.prank(address(uint160(controller) - 1));
        vm.expectRevert(CreditVaultProtocol.CVP_NotAuthorized.selector);
        cvp.forgiveAccountsStatusCheck(accounts);
    }
}
