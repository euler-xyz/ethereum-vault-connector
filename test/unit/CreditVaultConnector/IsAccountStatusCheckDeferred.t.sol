// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "src/test/CreditVaultConnectorHarness.sol";

contract IsAccountStatusCheckDeferredTest is Test {
    CreditVaultConnectorHarness internal cvc;

    function setUp() public {
        cvc = new CreditVaultConnectorHarness();
    }

    function test_IsAccountStatusCheckDeferred(
        uint8 numberOfAccounts,
        bytes memory seed
    ) external {
        vm.assume(numberOfAccounts <= Set.MAX_ELEMENTS);

        for (uint i = 0; i < numberOfAccounts; ++i) {
            // we're not in a batch thus the check will not get deferred
            cvc.setBatchDepth(0);

            address account = address(
                uint160(uint(keccak256(abi.encode(i, seed))))
            );
            assertFalse(cvc.isAccountStatusCheckDeferred(account));

            cvc.requireAccountStatusCheck(account);
            assertFalse(cvc.isAccountStatusCheckDeferred(account));

            // simulate being in a batch
            cvc.setBatchDepth(1);

            cvc.requireAccountStatusCheck(account);
            assertTrue(cvc.isAccountStatusCheckDeferred(account));
        }
    }
}
