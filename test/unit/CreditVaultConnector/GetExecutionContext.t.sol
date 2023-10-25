// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../cvc/CreditVaultConnectorHarness.sol";

contract GetExecutionContextTest is Test {
    CreditVaultConnectorHarness internal cvc;

    function setUp() public {
        cvc = new CreditVaultConnectorHarness();
    }

    function test_GetExecutionContext(address account, uint seed) external {
        vm.assume(account != address(0) && account != address(cvc));

        address controller = address(new Vault(cvc));

        (address onBehalfOfAccount, bool controllerEnabled) = cvc
            .getExecutionContext(controller);
        uint context = cvc.getRawExecutionContext();

        assertEq(onBehalfOfAccount, address(0));
        assertFalse(controllerEnabled);
        assertEq(context, 1 << 208);

        if (seed % 2 == 0) {
            vm.prank(account);
            cvc.enableController(account, controller);
        }

        cvc.setBatchDepth(seed % 3 == 0 ? 1 : 0);
        cvc.setOnBehalfOfAccount(account);
        cvc.setChecksLock(false);
        cvc.setImpersonateLock(seed % 4 == 0 ? true : false);
        cvc.setOperatorAuthenticated(seed % 5 == 0 ? true : false);
        cvc.setPermit(seed % 6 == 0 ? true : false);
        cvc.setSimulation(seed % 7 == 0 ? true : false);

        (onBehalfOfAccount, controllerEnabled) = cvc.getExecutionContext(
            controller
        );
        context = cvc.getRawExecutionContext();

        assertEq(onBehalfOfAccount, account);
        assertEq(controllerEnabled, seed % 2 == 0 ? true : false);
        assertEq(
            context &
                0x00000000000000000000000000000000000000000000000000000000000000FF,
            seed % 3 == 0 ? 1 : 0
        );
        assertEq(
            context &
                0x0000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00,
            uint(uint160(account)) << 8
        );
        assertEq(
            context &
                0x00000000000000000000FF000000000000000000000000000000000000000000 !=
                0,
            false
        );
        assertEq(
            context &
                0x000000000000000000FF00000000000000000000000000000000000000000000 !=
                0,
            seed % 4 == 0 ? true : false
        );
        assertEq(
            context &
                0x0000000000000000FF0000000000000000000000000000000000000000000000 !=
                0,
            seed % 5 == 0 ? true : false
        );
        assertEq(
            context &
                0x00000000000000FF000000000000000000000000000000000000000000000000 !=
                0,
            seed % 6 == 0 ? true : false
        );
        assertEq(
            context &
                0x000000000000FF00000000000000000000000000000000000000000000000000 !=
                0,
            seed % 7 == 0 ? true : false
        );
    }
}
