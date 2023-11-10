// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../evc/EthereumVaultConnectorHarness.sol";

contract IsVaultStatusCheckDeferredTest is Test {
    EthereumVaultConnectorHarness internal evc;

    function setUp() public {
        evc = new EthereumVaultConnectorHarness();
    }

    function test_IsVaultStatusCheckDeferred(uint8 numberOfVaults) external {
        vm.assume(numberOfVaults <= Set.MAX_ELEMENTS);

        for (uint i = 0; i < numberOfVaults; ++i) {
            // we're not in a batch thus the check will not get deferred
            evc.setCallDepth(0);

            address vault = address(new Vault(evc));
            assertFalse(evc.isVaultStatusCheckDeferred(vault));

            vm.prank(vault);
            evc.requireVaultStatusCheck();
            assertFalse(evc.isVaultStatusCheckDeferred(vault));

            // simulate being in a batch
            evc.setCallDepth(1);

            vm.prank(vault);
            evc.requireVaultStatusCheck();
            assertTrue(evc.isVaultStatusCheckDeferred(vault));

            evc.reset();
        }
    }
}
