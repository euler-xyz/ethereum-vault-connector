// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../../utils/CreditVaultProtocolHarnessed.sol";

contract IsVaultStatusCheckDeferredTest is Test {
    CreditVaultProtocolHarnessed internal cvp;

    function setUp() public {
        cvp = new CreditVaultProtocolHarnessed();
    }

    function test_IsVaultStatusCheckDeferred(uint8 numberOfVaults) external {
        vm.assume(numberOfVaults <= Set.MAX_ELEMENTS);

        for (uint i = 0; i < numberOfVaults; ++i) {
            // we're not in a batch thus the check will not get deferred
            cvp.setBatchDepth(0);

            address vault = address(new Vault(cvp));
            assertFalse(cvp.isVaultStatusCheckDeferred(vault));

            vm.prank(vault);
            cvp.requireVaultStatusCheck();
            assertFalse(cvp.isVaultStatusCheckDeferred(vault));

            // simulate being in a batch
            cvp.setBatchDepth(1);

            vm.prank(vault);
            cvp.requireVaultStatusCheck();
            assertTrue(cvp.isVaultStatusCheckDeferred(vault));
        }
    }
}
