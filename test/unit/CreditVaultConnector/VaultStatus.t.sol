// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

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
            // controller returning false and reverting
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
            // controller returning false and reverting
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
}
