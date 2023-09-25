// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../../src/test/CreditVaultConnectorHarness.sol";

contract IsVaultStatusCheckDeferredTest is Test {
    CreditVaultConnectorHarness internal cvc;

    function setUp() public {
        cvc = new CreditVaultConnectorHarness();
    }

    function test_IsVaultStatusCheckDeferred(uint8 numberOfVaults) external {
        vm.assume(numberOfVaults <= Set.MAX_ELEMENTS);

        for (uint i = 0; i < numberOfVaults; ++i) {
            // we're not in a batch thus the check will not get deferred
            cvc.setBatchDepth(0);

            address vault = address(new Vault(cvc));
            assertFalse(cvc.isVaultStatusCheckDeferred(vault));

            vm.prank(vault);
            cvc.requireVaultStatusCheck();
            assertFalse(cvc.isVaultStatusCheckDeferred(vault));

            // simulate being in a batch
            cvc.setBatchDepth(1);

            vm.prank(vault);
            cvc.requireVaultStatusCheck();
            assertTrue(cvc.isVaultStatusCheckDeferred(vault));
        }
    }
}
