// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity =0.8.19;

import "forge-std/Test.sol";
import "../../evc/EthereumVaultConnectorHarness.sol";

contract VaultStatusTest is Test {
    EthereumVaultConnectorHarness internal evc;

    function setUp() public {
        evc = new EthereumVaultConnectorHarness();
    }

    function test_RequireVaultStatusCheck(uint8 vaultsNumber, bool allStatusesValid) external {
        vm.assume(vaultsNumber > 0 && vaultsNumber <= Set.MAX_ELEMENTS);

        for (uint256 i = 0; i < vaultsNumber; i++) {
            address vault = address(new Vault(evc));

            // check all the options: vault state is ok, vault state is violated with
            // vault returning false and reverting
            Vault(vault).setVaultStatusState(
                allStatusesValid ? 0 : uint160(vault) % 3 == 0 ? 0 : uint160(vault) % 3 == 1 ? 1 : 2
            );

            vm.prank(vault);
            if (!(allStatusesValid || uint160(vault) % 3 == 0)) {
                vm.expectRevert(
                    uint160(vault) % 3 == 1 ? bytes("vault status violation") : abi.encode(bytes4(uint32(1)))
                );
            }
            evc.requireVaultStatusCheck();
            evc.verifyVaultStatusChecks();
            evc.clearExpectedChecks();
        }
    }

    function test_WhenDeferred_RequireVaultStatusCheck(uint8 vaultsNumber, bool allStatusesValid) external {
        vm.assume(vaultsNumber > 0 && vaultsNumber <= Set.MAX_ELEMENTS);

        for (uint256 i = 0; i < vaultsNumber; i++) {
            address vault = address(new Vault(evc));

            // check all the options: vault state is ok, vault state is violated with
            // vault returning false and reverting
            Vault(vault).setVaultStatusState(
                allStatusesValid ? 0 : uint160(vault) % 3 == 0 ? 0 : uint160(vault) % 3 == 1 ? 1 : 2
            );

            Vault(vault).setVaultStatusState(1);
            evc.setCallDepth(1);

            vm.prank(vault);

            // even though the vault status state was set to 1 which should revert,
            // it doesn't because in checks deferral we only add the vaults to the set
            // so that the checks can be performed later
            evc.requireVaultStatusCheck();

            if (!(allStatusesValid || uint160(vault) % 3 == 0)) {
                // checks no longer deferred
                evc.setCallDepth(0);

                vm.prank(vault);
                vm.expectRevert(bytes("vault status violation"));
                evc.requireVaultStatusCheck();
            }
        }
    }

    function test_RevertIfChecksReentrancy_RequireVaultStatusCheck(uint8 index, uint8 vaultsNumber) external {
        vm.assume(index < vaultsNumber);
        vm.assume(vaultsNumber > 0 && vaultsNumber <= Set.MAX_ELEMENTS);

        address[] memory vaults = new address[](vaultsNumber);
        for (uint256 i = 0; i < vaultsNumber; i++) {
            vaults[i] = address(new Vault(evc));
        }

        evc.setChecksLock(true);

        vm.prank(vaults[index]);
        vm.expectRevert(abi.encodeWithSelector(Errors.EVC_ChecksReentrancy.selector));
        evc.requireVaultStatusCheck();

        evc.setChecksLock(false);
        vm.prank(vaults[index]);
        evc.requireVaultStatusCheck();
    }

    function test_AcquireChecksLock_RequireVaultStatusChecks(uint8 numberOfVaults) external {
        vm.assume(numberOfVaults > 0 && numberOfVaults <= Set.MAX_ELEMENTS);

        address[] memory vaults = new address[](numberOfVaults);
        for (uint256 i = 0; i < numberOfVaults; i++) {
            vaults[i] = address(new VaultMalicious(evc));

            VaultMalicious(vaults[i]).setExpectedErrorSelector(Errors.EVC_ChecksReentrancy.selector);

            vm.prank(vaults[i]);
            // function will revert with EVC_VaultStatusViolation according to VaultMalicious implementation
            vm.expectRevert(bytes("malicious vault"));
            evc.requireVaultStatusCheck();
        }
    }

    function test_RequireVaultStatusCheckNow(uint8 vaultsNumber, bool allStatusesValid) external {
        vm.assume(vaultsNumber > 0 && vaultsNumber <= Set.MAX_ELEMENTS);

        address[] memory vaults = new address[](vaultsNumber);
        for (uint256 i = 0; i < vaultsNumber; i++) {
            vaults[i] = address(new Vault(evc));
            address vault = vaults[i];

            // check all the options: vault state is ok, vault state is violated with
            // vault returning false and reverting
            Vault(vault).setVaultStatusState(
                allStatusesValid ? 0 : uint160(vault) % 3 == 0 ? 0 : uint160(vault) % 3 == 1 ? 1 : 2
            );

            // first, schedule the check to be performed later to prove that after being performed on the fly
            // vault is no longer contained in the set to be performed later
            evc.setCallDepth(1);

            vm.prank(vault);
            evc.requireVaultStatusCheck();

            Vault(vault).clearChecks();
            evc.clearExpectedChecks();

            assertTrue(evc.isVaultStatusCheckDeferred(vault));
            vm.prank(vault);
            if (!(allStatusesValid || uint160(vault) % 3 == 0)) {
                vm.expectRevert(
                    uint160(vault) % 3 == 1 ? bytes("vault status violation") : abi.encode(bytes4(uint32(1)))
                );
            }
            evc.requireVaultStatusCheckNow();

            if (allStatusesValid || uint160(vault) % 3 == 0) {
                assertFalse(evc.isVaultStatusCheckDeferred(vault));
            } else {
                assertTrue(evc.isVaultStatusCheckDeferred(vault));
            }
            evc.verifyVaultStatusChecks();
        }

        // schedule the checks to be performed later to prove that after being performed on the fly
        // vaults are no longer contained in the set to be performed later
        evc.setCallDepth(1);
        for (uint256 i = 0; i < vaultsNumber; i++) {
            address vault = vaults[i];
            vm.prank(vault);
            evc.requireVaultStatusCheck();
            Vault(vault).clearChecks();
            assertTrue(evc.isVaultStatusCheckDeferred(vault));
        }
        evc.clearExpectedChecks();

        for (uint256 i = 0; i < vaultsNumber; i++) {
            address vault = vaults[i];

            vm.prank(vault);
            if (!(allStatusesValid || uint160(vault) % 3 == 0)) {
                vm.expectRevert(
                    uint160(vault) % 3 == 1 ? bytes("vault status violation") : abi.encode(bytes4(uint32(1)))
                );
            }
            evc.requireVaultStatusCheckNow();

            if (allStatusesValid || uint160(vault) % 3 == 0) {
                assertFalse(evc.isVaultStatusCheckDeferred(vault));
            } else {
                assertTrue(evc.isVaultStatusCheckDeferred(vault));
            }
        }
        evc.verifyVaultStatusChecks();
    }

    function test_RevertIfChecksReentrancy_RequireVaultStatusCheckNow(uint8 numberOfVaults) external {
        vm.assume(numberOfVaults > 0 && numberOfVaults <= Set.MAX_ELEMENTS);

        address[] memory vaults = new address[](numberOfVaults);
        for (uint256 i = 0; i < numberOfVaults; i++) {
            vaults[i] = address(new Vault(evc));

            evc.setChecksLock(true);
            vm.prank(vaults[i]);
            vm.expectRevert(abi.encodeWithSelector(Errors.EVC_ChecksReentrancy.selector));
            evc.requireVaultStatusCheckNow();

            evc.setChecksLock(false);
            vm.prank(vaults[i]);
            evc.requireVaultStatusCheckNow();
        }
    }

    function test_AcquireChecksLock_RequireVaultStatusChecksNow(uint8 numberOfVaults) external {
        vm.assume(numberOfVaults > 0 && numberOfVaults <= Set.MAX_ELEMENTS);

        for (uint256 i = 0; i < numberOfVaults; i++) {
            address vault = address(new VaultMalicious(evc));

            evc.setCallDepth(1);

            vm.prank(vault);
            evc.requireVaultStatusCheck();

            VaultMalicious(vault).setExpectedErrorSelector(Errors.EVC_ChecksReentrancy.selector);

            // function will revert with EVC_VaultStatusViolation according to VaultMalicious implementation
            vm.prank(vault);
            vm.expectRevert(bytes("malicious vault"));
            evc.requireVaultStatusCheckNow();
        }
    }

    function test_RequireAllVaultsStatusCheckNow(uint8 numberOfVaults, bool allStatusesValid) external {
        vm.assume(numberOfVaults > 0 && numberOfVaults <= Set.MAX_ELEMENTS);

        address[] memory vaults = new address[](numberOfVaults);
        for (uint256 i = 0; i < numberOfVaults; i++) {
            vaults[i] = address(new Vault(evc));
        }

        uint256 invalidVaultsCounter;
        address[] memory invalidVaults = new address[](numberOfVaults);

        for (uint256 i = 0; i < numberOfVaults; i++) {
            address vault = vaults[i];

            evc.reset();
            evc.setCallDepth(0);

            // check all the options: vault state is ok, vault state is violated with
            // vault returning false and reverting
            Vault(vault).setVaultStatusState(
                allStatusesValid ? 0 : uint160(vault) % 3 == 0 ? 0 : uint160(vault) % 3 == 1 ? 1 : 2
            );

            evc.setCallDepth(1);

            vm.prank(vault);
            evc.requireVaultStatusCheck();

            Vault(vault).clearChecks();
            evc.clearExpectedChecks();

            assertTrue(evc.isVaultStatusCheckDeferred(vault));
            if (!(allStatusesValid || uint160(vault) % 3 == 0)) {
                // for later check
                invalidVaults[invalidVaultsCounter++] = vault;

                vm.expectRevert(
                    uint160(vault) % 3 == 1 ? bytes("vault status violation") : abi.encode(bytes4(uint32(1)))
                );
            }
            evc.requireAllVaultsStatusCheckNow();

            if (allStatusesValid || uint160(vault) % 3 == 0) {
                assertFalse(evc.isVaultStatusCheckDeferred(vault));
            } else {
                assertTrue(evc.isVaultStatusCheckDeferred(vault));
            }
            evc.verifyVaultStatusChecks();
        }

        evc.reset();

        evc.setCallDepth(1);
        for (uint256 i = 0; i < vaults.length; ++i) {
            vm.prank(vaults[i]);
            evc.requireVaultStatusCheck();
            Vault(vaults[i]).clearChecks();
        }
        evc.clearExpectedChecks();

        for (uint256 i = 0; i < vaults.length; ++i) {
            assertTrue(evc.isVaultStatusCheckDeferred(vaults[i]));
        }
        if (invalidVaultsCounter > 0) {
            vm.expectRevert(
                uint160(invalidVaults[0]) % 3 == 1 ? bytes("vault status violation") : abi.encode(bytes4(uint32(1)))
            );
        }
        evc.requireAllVaultsStatusCheckNow();
        for (uint256 i = 0; i < vaults.length; ++i) {
            assertEq(evc.isVaultStatusCheckDeferred(vaults[i]), invalidVaultsCounter > 0);
        }
        evc.verifyVaultStatusChecks();
    }

    function test_RevertIfChecksReentrancy_RequireAllVaultsStatusCheckNow(bool locked) external {
        evc.setChecksLock(locked);

        if (locked) {
            vm.expectRevert(abi.encodeWithSelector(Errors.EVC_ChecksReentrancy.selector));
        }
        evc.requireAllVaultsStatusCheckNow();
    }

    function test_AcquireChecksLock_RequireAllVaultsStatusChecksNow(uint8 numberOfVaults) external {
        vm.assume(numberOfVaults > 0 && numberOfVaults <= Set.MAX_ELEMENTS);

        address[] memory vaults = new address[](numberOfVaults);
        for (uint256 i = 0; i < numberOfVaults; i++) {
            vaults[i] = address(new VaultMalicious(evc));

            evc.setCallDepth(1);

            vm.prank(vaults[i]);
            evc.requireVaultStatusCheck();

            VaultMalicious(vaults[i]).setExpectedErrorSelector(Errors.EVC_ChecksReentrancy.selector);
        }

        vm.expectRevert(bytes("malicious vault"));
        evc.requireAllVaultsStatusCheckNow();
    }

    function test_ForgiveVaultStatusCheck(uint8 vaultsNumber) external {
        vm.assume(vaultsNumber > 0 && vaultsNumber <= Set.MAX_ELEMENTS);

        for (uint256 i = 0; i < vaultsNumber; i++) {
            address vault = address(new Vault(evc));

            // vault status check will be scheduled for later due to deferred state
            evc.setCallDepth(1);

            vm.prank(vault);
            evc.requireVaultStatusCheck();

            assertTrue(evc.isVaultStatusCheckDeferred(vault));
            vm.prank(vault);
            evc.forgiveVaultStatusCheck();
            assertFalse(evc.isVaultStatusCheckDeferred(vault));
        }
    }

    function test_RevertIfChecksReentrancy_ForgiveVaultStatusCheck(bool locked) external {
        evc.setChecksLock(locked);

        if (locked) {
            vm.expectRevert(abi.encodeWithSelector(Errors.EVC_ChecksReentrancy.selector));
        }
        evc.forgiveVaultStatusCheck();
    }
}
