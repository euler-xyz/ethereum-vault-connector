// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../evc/EthereumVaultConnectorHarness.sol";

contract AccountAndVaultStatusTest is Test {
    EthereumVaultConnectorHarness internal evc;

    function setUp() public {
        evc = new EthereumVaultConnectorHarness();
    }

    function test_RequireAccountAndVaultStatusCheck(
        uint8 numberOfAddresses,
        bytes memory seed,
        bool allStatusesValid
    ) external {
        vm.assume(numberOfAddresses > 0 && numberOfAddresses <= Set.MAX_ELEMENTS);

        address[] memory accounts = new address[](numberOfAddresses);
        address[] memory controllers = new address[](numberOfAddresses);
        address[] memory vaults = new address[](numberOfAddresses);
        for (uint256 i = 0; i < numberOfAddresses; i++) {
            accounts[i] = address(uint160(uint256(keccak256(abi.encode(i, seed)))));
            controllers[i] = address(new Vault(evc));
            vaults[i] = address(new Vault(evc));
        }

        for (uint256 i = 0; i < numberOfAddresses; i++) {
            address account = accounts[i];
            address controller = controllers[i];
            address vault = vaults[i];

            vm.prank(account);
            evc.enableController(account, controller);
            Vault(controller).clearChecks();
            evc.clearExpectedChecks();

            // check all the options: states are ok, states are violated with
            // vault/controller returning false and reverting
            Vault(controller).setAccountStatusState(
                allStatusesValid ? 0 : uint160(account) % 3 == 0 ? 0 : uint160(account) % 3 == 1 ? 1 : 2
            );

            Vault(vault).setVaultStatusState(
                allStatusesValid ? 0 : uint160(vault) % 3 == 0 ? 0 : uint160(vault) % 3 == 1 ? 1 : 2
            );

            bool alredyExpectsRevert;
            if (!(allStatusesValid || uint160(account) % 3 == 0)) {
                alredyExpectsRevert = true;

                vm.expectRevert(
                    uint160(account) % 3 == 1 ? bytes("account status violation") : abi.encode(bytes4(uint32(2)))
                );
            }

            if (!(allStatusesValid || uint160(vault) % 3 == 0) && !alredyExpectsRevert) {
                vm.expectRevert(
                    uint160(vault) % 3 == 1 ? bytes("vault status violation") : abi.encode(bytes4(uint32(1)))
                );
            }

            vm.prank(vault);
            evc.requireAccountAndVaultStatusCheck(account);

            evc.verifyAccountStatusChecks();
            evc.verifyVaultStatusChecks();
            Vault(controller).clearChecks();
            Vault(vault).clearChecks();
            evc.clearExpectedChecks();
        }
    }

    function test_WhenDeferred_RequireAccountAndVaultStatusCheck(uint8 numberOfAddresses, bytes memory seed) external {
        vm.assume(numberOfAddresses > 0 && numberOfAddresses <= Set.MAX_ELEMENTS);

        address[] memory accounts = new address[](numberOfAddresses);
        address[] memory controllers = new address[](numberOfAddresses);
        address[] memory vaults = new address[](numberOfAddresses);
        for (uint256 i = 0; i < numberOfAddresses; i++) {
            accounts[i] = address(uint160(uint256(keccak256(abi.encode(i, seed)))));
            controllers[i] = address(new Vault(evc));
            vaults[i] = address(new Vault(evc));
        }

        for (uint256 i = 0; i < numberOfAddresses; i++) {
            evc.setCallDepth(0);

            address account = accounts[i];
            address controller = controllers[i];
            address vault = vaults[i];

            vm.prank(account);
            evc.enableController(account, controller);
            Vault(controller).setAccountStatusState(1);
            Vault(vault).setVaultStatusState(1);

            // status checks will be scheduled for later due to deferred state
            evc.setCallDepth(1);

            // even though the account status state and the vault status state were
            // set to 1 which should revert, it doesn't because in checks deferral
            // we only add the accounts to the set so that the checks can be performed
            // later
            assertFalse(evc.isAccountStatusCheckDeferred(account));
            assertFalse(evc.isVaultStatusCheckDeferred(vault));

            vm.prank(vault);
            evc.requireAccountAndVaultStatusCheck(account);

            assertTrue(evc.isAccountStatusCheckDeferred(account));
            assertTrue(evc.isVaultStatusCheckDeferred(vault));

            evc.reset();
        }
    }

    function test_RevertIfChecksReentrancy_RequireAccountAndVaultStatusCheck(
        uint8 index,
        address[] calldata accounts
    ) external {
        vm.assume(index < accounts.length);
        vm.assume(accounts.length > 0 && accounts.length <= Set.MAX_ELEMENTS);

        address vault = address(new Vault(evc));

        evc.setChecksLock(true);

        vm.expectRevert(abi.encodeWithSelector(Errors.EVC_ChecksReentrancy.selector));
        vm.prank(vault);
        evc.requireAccountAndVaultStatusCheck(accounts[index]);

        evc.setChecksLock(false);
        vm.prank(vault);
        evc.requireAccountAndVaultStatusCheck(accounts[index]);
    }

    function test_AcquireChecksLock_RequireAccountAndVaultStatusChecks(
        uint8 numberOfAddresses,
        bytes memory seed
    ) external {
        vm.assume(numberOfAddresses > 0 && numberOfAddresses <= Set.MAX_ELEMENTS);

        address[] memory accounts = new address[](numberOfAddresses);
        address[] memory controllers = new address[](numberOfAddresses);
        address[] memory vaults = new address[](numberOfAddresses);
        for (uint256 i = 0; i < numberOfAddresses; i++) {
            accounts[i] = address(uint160(uint256(keccak256(abi.encode(i, seed)))));

            controllers[i] = address(new VaultMalicious(evc));
            vaults[i] = address(new VaultMalicious(evc));

            vm.prank(accounts[i]);
            evc.enableController(accounts[i], controllers[i]);

            VaultMalicious(controllers[i]).setExpectedErrorSelector(Errors.EVC_ChecksReentrancy.selector);

            // function will revert with EVC_AccountStatusViolation according to VaultMalicious implementation
            vm.expectRevert(bytes("malicious vault"));
            vm.prank(vaults[i]);
            evc.requireAccountAndVaultStatusCheck(accounts[i]);
        }
    }
}
