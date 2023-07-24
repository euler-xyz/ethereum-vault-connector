// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../../utils/CreditVaultProtocolHarnessed.sol";

contract VaultStatusTest is Test {
    CreditVaultProtocolHarnessed internal cvp;

    function setUp() public {
        cvp = new CreditVaultProtocolHarnessed();
    }

    function test_RequireVaultStatusCheck(uint8 vaultsNumber, bool allStatusesValid) external {
        vm.assume(vaultsNumber > 0 && vaultsNumber <= Set.MAX_ELEMENTS);
        
        for (uint i = 0; i < vaultsNumber; i++) {
            address vault = address(new Vault(cvp));

            // check all the options: vault state is ok, vault state is violated with
            // controller returning false and reverting
            Vault(vault).setVaultStatusState(
                allStatusesValid
                ? 0
                : uint160(vault) % 3 == 0
                    ? 0
                    : uint160(vault) % 3 == 1
                        ? 1
                        : 2
            );

            vm.prank(vault);
            if (!(allStatusesValid || uint160(vault) % 3 == 0)) {
                vm.expectRevert(abi.encodeWithSelector(
                    CreditVaultProtocol.CVP_VaultStatusViolation.selector,
                    vault,
                    uint160(vault) % 3 == 1
                        ? bytes("vault status violation")
                        : abi.encodeWithSignature("Error(string)", bytes("invalid vault"))
                ));
            }
            cvp.requireVaultStatusCheck();
            cvp.verifyVaultStatusChecks();
            cvp.clearExpectedChecks();
        }
    }

    function test_WhenDeferred_RequireVaultStatusCheck(uint8 vaultsNumber, bool allStatusesValid) external {
        vm.assume(vaultsNumber > 0 && vaultsNumber <= Set.MAX_ELEMENTS);
        
        for (uint i = 0; i < vaultsNumber; i++) {
            address vault = address(new Vault(cvp));

            // check all the options: vault state is ok, vault state is violated with
            // controller returning false and reverting
            Vault(vault).setVaultStatusState(
                allStatusesValid
                ? 0
                : uint160(vault) % 3 == 0
                    ? 0
                    : uint160(vault) % 3 == 1
                        ? 1
                        : 2
            );

            Vault(vault).setVaultStatusState(1);
            cvp.setBatchDepth(2);

            vm.prank(vault);

            // even though the vault status state was set to 1 which should revert,
            // it doesn't because in checks deferral we only add the vaults to the set
            // so that the checks can be performed later
            cvp.requireVaultStatusCheck();

            if (!(allStatusesValid || uint160(vault) % 3 == 0)) {
                // checks no longer deferred
                cvp.setBatchDepth(1);

                vm.prank(vault);
                vm.expectRevert(abi.encodeWithSelector(
                    CreditVaultProtocol.CVP_VaultStatusViolation.selector,
                    vault,
                    "vault status violation"
                ));
                cvp.requireVaultStatusCheck();
            }
        }
    }
}
