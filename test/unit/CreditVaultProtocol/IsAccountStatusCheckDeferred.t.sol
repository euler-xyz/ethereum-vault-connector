// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../../utils/CreditVaultProtocolHarnessed.sol";

contract IsAccountStatusCheckDeferredTest is Test {
    CreditVaultProtocolHarnessed internal cvp;

    function setUp() public {
        cvp = new CreditVaultProtocolHarnessed();
    }

    function test_IsAccountStatusCheckDeferred(
        uint8 numberOfAccounts,
        bytes memory seed
    ) external {
        vm.assume(numberOfAccounts <= Set.MAX_ELEMENTS);

        for (uint i = 0; i < numberOfAccounts; ++i) {
            // we're not in a batch thus the check will not get deferred
            cvp.setBatchDepth(1);

            address account = address(
                uint160(uint(keccak256(abi.encode(i, seed))))
            );
            assertFalse(cvp.isAccountStatusCheckDeferred(account));

            cvp.requireAccountStatusCheck(account);
            assertFalse(cvp.isAccountStatusCheckDeferred(account));

            // simulate being in a batch
            cvp.setBatchDepth(2);

            cvp.requireAccountStatusCheck(account);
            assertTrue(cvp.isAccountStatusCheckDeferred(account));
        }
    }
}
