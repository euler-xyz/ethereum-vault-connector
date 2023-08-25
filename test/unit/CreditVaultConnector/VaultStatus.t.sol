// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "src/test/CreditVaultConnectorHarness.sol";

contract VaultStatusTest is Test {
    CreditVaultConnectorHarness internal cvc;

    function setUp() public {
        cvc = new CreditVaultConnectorHarness();
    }

    function test_RequireVaultStatusCheck(
        uint8 vaultsNumber,
        bool allStatusesValid
    ) external {
        vm.assume(vaultsNumber > 0 && vaultsNumber <= Set.MAX_ELEMENTS);

        for (uint i = 0; i < vaultsNumber; i++) {
            address vault = address(new Vault(cvc));

            // check all the options: vault state is ok, vault state is violated with
            // vault returning false and reverting
            Vault(vault).setVaultStatusState(
                allStatusesValid ? 0 : uint160(vault) % 3 == 0
                    ? 0
                    : uint160(vault) % 3 == 1
                    ? 1
                    : 2
            );

            vm.prank(vault);
            if (!(allStatusesValid || uint160(vault) % 3 == 0)) {
                vm.expectRevert(
                    abi.encodeWithSelector(
                        CreditVaultConnector.CVC_VaultStatusViolation.selector,
                        vault,
                        uint160(vault) % 3 == 1
                            ? bytes("vault status violation")
                            : abi.encodeWithSignature(
                                "Error(string)",
                                bytes("invalid vault")
                            )
                    )
                );
            }
            cvc.requireVaultStatusCheck();
            cvc.verifyVaultStatusChecks();
            cvc.clearExpectedChecks();
        }
    }

    function test_WhenDeferred_RequireVaultStatusCheck(
        uint8 vaultsNumber,
        bool allStatusesValid
    ) external {
        vm.assume(vaultsNumber > 0 && vaultsNumber <= Set.MAX_ELEMENTS);

        for (uint i = 0; i < vaultsNumber; i++) {
            address vault = address(new Vault(cvc));

            // check all the options: vault state is ok, vault state is violated with
            // vault returning false and reverting
            Vault(vault).setVaultStatusState(
                allStatusesValid ? 0 : uint160(vault) % 3 == 0
                    ? 0
                    : uint160(vault) % 3 == 1
                    ? 1
                    : 2
            );

            Vault(vault).setVaultStatusState(1);
            cvc.setBatchDepth(1);

            vm.prank(vault);

            // even though the vault status state was set to 1 which should revert,
            // it doesn't because in checks deferral we only add the vaults to the set
            // so that the checks can be performed later
            cvc.requireVaultStatusCheck();

            if (!(allStatusesValid || uint160(vault) % 3 == 0)) {
                // checks no longer deferred
                cvc.setBatchDepth(0);

                vm.prank(vault);
                vm.expectRevert(
                    abi.encodeWithSelector(
                        CreditVaultConnector.CVC_VaultStatusViolation.selector,
                        vault,
                        "vault status violation"
                    )
                );
                cvc.requireVaultStatusCheck();
            }
        }
    }

    function test_RevertIfChecksReentrancy_RequireVaultStatusCheck(
        uint8 index,
        uint8 vaultsNumber
    ) external {
        vm.assume(index < vaultsNumber);
        vm.assume(vaultsNumber > 0 && vaultsNumber <= Set.MAX_ELEMENTS);

        address[] memory vaults = new address[](vaultsNumber);
        for (uint i = 0; i < vaultsNumber; i++) {
            vaults[i] = address(new Vault(cvc));
        }

        cvc.setChecksLock(true);

        vm.prank(vaults[index]);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            )
        );
        cvc.requireVaultStatusCheck();

        cvc.setChecksLock(false);
        vm.prank(vaults[index]);
        cvc.requireVaultStatusCheck();
    }

    function test_AcquireChecksLock_RequireVaultStatusChecks(
        uint8 numberOfVaults
    ) external {
        vm.assume(numberOfVaults > 0 && numberOfVaults <= Set.MAX_ELEMENTS);

        address[] memory vaults = new address[](numberOfVaults);
        for (uint i = 0; i < numberOfVaults; i++) {
            vaults[i] = address(new VaultMalicious(cvc));

            VaultMalicious(vaults[i]).setExpectedErrorSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            );

            vm.prank(vaults[i]);
            // function will revert with CVC_VaultStatusViolation according to VaultMalicious implementation
            vm.expectRevert(
                abi.encodeWithSelector(
                    CreditVaultConnector.CVC_VaultStatusViolation.selector,
                    vaults[i],
                    "malicious vault"
                )
            );
            cvc.requireVaultStatusCheck();
        }
    }

    function test_RequireVaultsStatusCheckNow(
        uint8 vaultsNumber,
        uint notRequestedVaultIndex,
        bool allStatusesValid
    ) external {
        vm.assume(vaultsNumber > 0 && vaultsNumber <= Set.MAX_ELEMENTS);
        vm.assume(notRequestedVaultIndex < vaultsNumber);

        address[] memory vaults = new address[](vaultsNumber);
        for (uint i = 0; i < vaultsNumber; i++) {
            vaults[i] = address(new Vault(cvc));
        }

        uint invalidVaultsCounter;
        address[] memory invalidVaults = new address[](vaultsNumber);

        for (uint i = 0; i < vaultsNumber; i++) {
            address vault = vaults[i];

            // check all the options: vault state is ok, vault state is violated with
            // vault returning false and reverting
            Vault(vault).setVaultStatusState(
                allStatusesValid ? 0 : uint160(vault) % 3 == 0
                    ? 0
                    : uint160(vault) % 3 == 1
                    ? 1
                    : 2
            );

            // first, schedule the check to be performed later to prove that after being peformed on the fly
            // vault is no longer contained in the set to be performed later
            cvc.setBatchDepth(1);

            vm.prank(vault);
            cvc.requireVaultStatusCheck();

            Vault(vault).clearChecks();
            cvc.clearExpectedChecks();

            assertTrue(cvc.isVaultStatusCheckDeferred(vault));
            if (!(allStatusesValid || uint160(vault) % 3 == 0)) {
                // for later check
                invalidVaults[invalidVaultsCounter++] = vault;

                vm.expectRevert(
                    abi.encodeWithSelector(
                        CreditVaultConnector.CVC_VaultStatusViolation.selector,
                        vault,
                        uint160(vault) % 3 == 1
                            ? bytes("vault status violation")
                            : abi.encodeWithSignature(
                                "Error(string)",
                                bytes("invalid vault")
                            )
                    )
                );
            }
            cvc.requireVaultStatusCheckNow(vault);

            if (allStatusesValid || uint160(vault) % 3 == 0) {
                assertFalse(cvc.isVaultStatusCheckDeferred(vault));
            } else {
                assertTrue(cvc.isVaultStatusCheckDeferred(vault));
            }
            cvc.verifyVaultStatusChecks();
        }

        // schedule the checks to be performed later to prove that after being peformed on the fly
        // vaults are no longer contained in the set to be performed later
        cvc.setBatchDepth(1);
        for (uint i = 0; i < vaultsNumber; i++) {
            address vault = vaults[i];
            vm.prank(vault);
            cvc.requireVaultStatusCheck();
            Vault(vault).clearChecks();
        }
        cvc.clearExpectedChecks();

        for (uint i = 0; i < vaultsNumber; ++i) {
            assertTrue(cvc.isVaultStatusCheckDeferred(vaults[i]));
        }
        if (invalidVaultsCounter > 0) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    CreditVaultConnector.CVC_VaultStatusViolation.selector,
                    invalidVaults[0],
                    uint160(invalidVaults[0]) % 3 == 1
                        ? bytes("vault status violation")
                        : abi.encodeWithSignature(
                            "Error(string)",
                            bytes("invalid vault")
                        )
                )
            );
        }
        cvc.requireVaultsStatusCheckNow(vaults);
        for (uint i = 0; i < vaultsNumber; ++i) {
            assertEq(
                cvc.isVaultStatusCheckDeferred(vaults[i]),
                invalidVaultsCounter > 0
            );
        }
        cvc.verifyVaultStatusChecks();

        // verify that the checks are not being performed if they hadn't been requested before
        cvc.reset();
        invalidVaults = new address[](vaultsNumber);
        delete invalidVaultsCounter;
        for (uint i = 0; i < vaultsNumber; i++) {
            address vault = vaults[i];

            cvc.setBatchDepth(1);

            if (i != notRequestedVaultIndex) {
                vm.prank(vault);
                cvc.requireVaultStatusCheck();
            }

            Vault(vault).clearChecks();
            cvc.clearExpectedChecks();

            assertEq(
                cvc.isVaultStatusCheckDeferred(vault),
                i != notRequestedVaultIndex
            );
            if (
                !(allStatusesValid || uint160(vault) % 3 == 0) &&
                i != notRequestedVaultIndex
            ) {
                // for later check
                invalidVaults[invalidVaultsCounter++] = vault;

                vm.expectRevert(
                    abi.encodeWithSelector(
                        CreditVaultConnector.CVC_VaultStatusViolation.selector,
                        vault,
                        uint160(vault) % 3 == 1
                            ? bytes("vault status violation")
                            : abi.encodeWithSignature(
                                "Error(string)",
                                bytes("invalid vault")
                            )
                    )
                );
            }
            cvc.requireVaultStatusCheckNow(vault);

            if (
                !(!(allStatusesValid || uint160(vault) % 3 == 0) &&
                    i != notRequestedVaultIndex)
            ) {
                assertFalse(cvc.isVaultStatusCheckDeferred(vault));
            } else {
                assertTrue(cvc.isVaultStatusCheckDeferred(vault));
            }
            cvc.verifyVaultStatusChecks();

            if (i == notRequestedVaultIndex) {
                assertEq(Vault(vault).getVaultStatusChecked().length, 0);
            }
        }

        cvc.setBatchDepth(1);
        for (uint i = 0; i < vaultsNumber; i++) {
            address vault = vaults[i];

            if (i != notRequestedVaultIndex) {
                vm.prank(vault);
                cvc.requireVaultStatusCheck();
            }

            Vault(vault).clearChecks();
        }
        cvc.clearExpectedChecks();

        for (uint i = 0; i < vaultsNumber; ++i) {
            assertEq(
                cvc.isVaultStatusCheckDeferred(vaults[i]),
                i != notRequestedVaultIndex
            );
        }
        if (invalidVaultsCounter > 0) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    CreditVaultConnector.CVC_VaultStatusViolation.selector,
                    invalidVaults[0],
                    uint160(invalidVaults[0]) % 3 == 1
                        ? bytes("vault status violation")
                        : abi.encodeWithSignature(
                            "Error(string)",
                            bytes("invalid vault")
                        )
                )
            );
        }
        cvc.requireVaultsStatusCheckNow(vaults);
        for (uint i = 0; i < vaultsNumber; ++i) {
            assertEq(
                cvc.isVaultStatusCheckDeferred(vaults[i]),
                invalidVaultsCounter > 0 && i != notRequestedVaultIndex
            );
        }
        cvc.verifyVaultStatusChecks();
        assertEq(
            Vault(vaults[notRequestedVaultIndex])
                .getVaultStatusChecked()
                .length,
            0
        );
    }

    function test_RevertIfChecksReentrancy_RequireVaultssStatusCheckNow(
        uint8 index,
        address[] calldata vaults
    ) external {
        vm.assume(index < vaults.length);
        vm.assume(vaults.length > 0 && vaults.length <= Set.MAX_ELEMENTS);

        cvc.setChecksLock(true);

        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            )
        );
        cvc.requireVaultStatusCheckNow(vaults[index]);

        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            )
        );
        cvc.requireVaultsStatusCheckNow(vaults);

        cvc.setChecksLock(false);
        cvc.requireVaultStatusCheckNow(vaults[index]);
        cvc.requireVaultsStatusCheckNow(vaults);
    }

    function test_AcquireChecksLock_RequireVaultsStatusChecksNow(
        uint8 numberOfVaults
    ) external {
        vm.assume(numberOfVaults > 0 && numberOfVaults <= Set.MAX_ELEMENTS);

        address[] memory vaults = new address[](numberOfVaults);
        for (uint i = 0; i < numberOfVaults; i++) {
            vaults[i] = address(new VaultMalicious(cvc));

            cvc.setBatchDepth(1);

            vm.prank(vaults[i]);
            cvc.requireVaultStatusCheck();

            VaultMalicious(vaults[i]).setExpectedErrorSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            );

            // function will revert with CVC_VaultStatusViolation according to VaultMalicious implementation
            vm.expectRevert(
                abi.encodeWithSelector(
                    CreditVaultConnector.CVC_VaultStatusViolation.selector,
                    vaults[i],
                    "malicious vault"
                )
            );
            cvc.requireVaultStatusCheckNow(vaults[i]);
        }

        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_VaultStatusViolation.selector,
                vaults[0],
                "malicious vault"
            )
        );
        cvc.requireVaultsStatusCheckNow(vaults);
    }

    function test_RequireAllVaultsStatusCheckNow(
        uint8 numberOfVaults,
        bool allStatusesValid
    ) external {
        vm.assume(numberOfVaults > 0 && numberOfVaults <= Set.MAX_ELEMENTS);

        address[] memory vaults = new address[](numberOfVaults);
        for (uint i = 0; i < numberOfVaults; i++) {
            vaults[i] = address(new Vault(cvc));
        }

        uint invalidVaultsCounter;
        address[] memory invalidVaults = new address[](numberOfVaults);

        for (uint i = 0; i < numberOfVaults; i++) {
            address vault = vaults[i];

            cvc.reset();
            cvc.setBatchDepth(0);

            // check all the options: vault state is ok, vault state is violated with
            // vault returning false and reverting
            Vault(vault).setVaultStatusState(
                allStatusesValid ? 0 : uint160(vault) % 3 == 0
                    ? 0
                    : uint160(vault) % 3 == 1
                    ? 1
                    : 2
            );

            cvc.setBatchDepth(1);

            vm.prank(vault);
            cvc.requireVaultStatusCheck();

            Vault(vault).clearChecks();
            cvc.clearExpectedChecks();

            assertTrue(cvc.isVaultStatusCheckDeferred(vault));
            if (!(allStatusesValid || uint160(vault) % 3 == 0)) {
                // for later check
                invalidVaults[invalidVaultsCounter++] = vault;

                vm.expectRevert(
                    abi.encodeWithSelector(
                        CreditVaultConnector.CVC_VaultStatusViolation.selector,
                        vault,
                        uint160(vault) % 3 == 1
                            ? bytes("vault status violation")
                            : abi.encodeWithSignature(
                                "Error(string)",
                                bytes("invalid vault")
                            )
                    )
                );
            }
            cvc.requireAllVaultsStatusCheckNow();

            if (allStatusesValid || uint160(vault) % 3 == 0) {
                assertFalse(cvc.isVaultStatusCheckDeferred(vault));
            } else {
                assertTrue(cvc.isVaultStatusCheckDeferred(vault));
            }
            cvc.verifyVaultStatusChecks();
        }

        cvc.reset();

        cvc.setBatchDepth(1);
        for (uint i = 0; i < vaults.length; ++i) {
            vm.prank(vaults[i]);
            cvc.requireVaultStatusCheck();
            Vault(vaults[i]).clearChecks();
        }
        cvc.clearExpectedChecks();

        for (uint i = 0; i < vaults.length; ++i) {
            assertTrue(cvc.isVaultStatusCheckDeferred(vaults[i]));
        }
        if (invalidVaultsCounter > 0) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    CreditVaultConnector.CVC_VaultStatusViolation.selector,
                    invalidVaults[0],
                    uint160(invalidVaults[0]) % 3 == 1
                        ? bytes("vault status violation")
                        : abi.encodeWithSignature(
                            "Error(string)",
                            bytes("invalid vault")
                        )
                )
            );
        }
        cvc.requireAllVaultsStatusCheckNow();
        for (uint i = 0; i < vaults.length; ++i) {
            assertEq(
                cvc.isVaultStatusCheckDeferred(vaults[i]),
                invalidVaultsCounter > 0
            );
        }
        cvc.verifyVaultStatusChecks();
    }

    function test_RevertIfChecksReentrancy_RequireAllVaultsStatusCheckNow(
        bool locked
    ) external {
        cvc.setChecksLock(locked);

        if (locked)
            vm.expectRevert(
                abi.encodeWithSelector(
                    CreditVaultConnector.CVC_ChecksReentrancy.selector
                )
            );
        cvc.requireAllVaultsStatusCheckNow();
    }

    function test_AcquireChecksLock_RequireAllVaultsStatusChecksNow(
        uint8 numberOfVaults
    ) external {
        vm.assume(numberOfVaults > 0 && numberOfVaults <= Set.MAX_ELEMENTS);

        address[] memory vaults = new address[](numberOfVaults);
        for (uint i = 0; i < numberOfVaults; i++) {
            vaults[i] = address(new VaultMalicious(cvc));

            cvc.setBatchDepth(1);

            vm.prank(vaults[i]);
            cvc.requireVaultStatusCheck();

            VaultMalicious(vaults[i]).setExpectedErrorSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            );
        }

        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_VaultStatusViolation.selector,
                vaults[0],
                "malicious vault"
            )
        );
        cvc.requireAllVaultsStatusCheckNow();
    }

    function test_ForgiveVaultStatusCheck(uint8 vaultsNumber) external {
        vm.assume(vaultsNumber > 0 && vaultsNumber <= Set.MAX_ELEMENTS);

        for (uint i = 0; i < vaultsNumber; i++) {
            address vault = address(new Vault(cvc));

            // vault status check will be scheduled for later due to deferred state
            cvc.setBatchDepth(1);

            vm.prank(vault);
            cvc.requireVaultStatusCheck();

            assertTrue(cvc.isVaultStatusCheckDeferred(vault));
            vm.prank(vault);
            cvc.forgiveVaultStatusCheck();
            assertFalse(cvc.isVaultStatusCheckDeferred(vault));
        }
    }

    function test_RevertIfChecksReentrancy_ForgiveVaultStatusCheck(
        bool locked
    ) external {
        cvc.setChecksLock(locked);

        if (locked)
            vm.expectRevert(
                abi.encodeWithSelector(
                    CreditVaultConnector.CVC_ChecksReentrancy.selector
                )
            );
        cvc.forgiveVaultStatusCheck();
    }
}
