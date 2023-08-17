// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "src/test/CreditVaultConnectorHarness.sol";

contract GetExecutionContextTest is Test {
    CreditVaultConnectorHarness internal cvc;

    function setUp() public {
        cvc = new CreditVaultConnectorHarness();
    }

    function test_GetExecutionContext(address account, uint seed) external {
        vm.assume(account != address(0));

        address controller = address(new Vault(cvc));

        (ICVC.ExecutionContext memory context, bool controllerEnabled) = cvc
            .getExecutionContext(controller);

        assertEq(context.batchDepth, 0);
        assertFalse(context.impersonateLock);
        assertEq(context.onBehalfOfAccount, address(0));
        assertFalse(controllerEnabled);

        if (seed % 2 == 0) {
            vm.prank(account);
            cvc.enableController(account, controller);
        }

        cvc.setBatchDepth(seed % 3 == 0 ? 1 : 0);
        cvc.setImpersonateLock(seed % 4 == 0 ? true : false);
        cvc.setOnBehalfOfAccount(account);

        (context, controllerEnabled) = cvc.getExecutionContext(controller);

        assertEq(context.batchDepth, seed % 3 == 0 ? 1 : 0);
        assertEq(context.impersonateLock, seed % 4 == 0 ? true : false);
        assertEq(context.onBehalfOfAccount, account);
        assertEq(controllerEnabled, seed % 2 == 0 ? true : false);
    }
}
