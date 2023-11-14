// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../evc/EthereumVaultConnectorHarness.sol";

contract IsAccountStatusCheckDeferredTest is Test {
    EthereumVaultConnectorHarness internal evc;

    function setUp() public {
        evc = new EthereumVaultConnectorHarness();
    }

    function test_IsAccountStatusCheckDeferred(uint8 numberOfAccounts, bytes memory seed) external {
        vm.assume(numberOfAccounts <= Set.MAX_ELEMENTS);

        for (uint256 i = 0; i < numberOfAccounts; ++i) {
            // we're not in a batch thus the check will not get deferred
            evc.setCallDepth(0);

            address account = address(uint160(uint256(keccak256(abi.encode(i, seed)))));
            assertFalse(evc.isAccountStatusCheckDeferred(account));

            evc.requireAccountStatusCheck(account);
            assertFalse(evc.isAccountStatusCheckDeferred(account));

            // simulate being in a batch
            evc.setCallDepth(1);

            evc.requireAccountStatusCheck(account);
            assertTrue(evc.isAccountStatusCheckDeferred(account));

            evc.reset();
        }
    }
}
