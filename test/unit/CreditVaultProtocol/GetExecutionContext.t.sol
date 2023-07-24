// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../../utils/CreditVaultProtocolHarnessed.sol";

contract GetExecutionContextTest is Test {
    CreditVaultProtocolHarnessed internal cvp;

    function setUp() public {
        cvp = new CreditVaultProtocolHarnessed();
    }

    function test_GetExecutionContext(address account, uint seed) external {
        vm.assume(account != address(0));

        address controller = address(new Vault(cvp));

        (ICVP.ExecutionContext memory context, bool controllerEnabled) = cvp
            .getExecutionContext(controller);

        assertEq(context.batchDepth, 1);
        assertFalse(context.controllerToCollateralCall);
        assertEq(context.onBehalfOfAccount, address(0));
        assertFalse(controllerEnabled);

        cvp.setBatchDepth(seed % 2 == 0 ? 2 : 1);
        cvp.setControllerToCollateralCall(seed % 3 == 0 ? true : false);
        cvp.setIgnoreAccountStatusCheck(seed % 4 == 0 ? true : false);
        cvp.setOnBehalfOfAccount(account);
        if (seed % 5 == 0) {
            vm.prank(account);
            cvp.enableController(account, controller);
        }

        (context, controllerEnabled) = cvp.getExecutionContext(controller);

        assertEq(context.batchDepth, seed % 2 == 0 ? 2 : 1);
        assertEq(
            context.controllerToCollateralCall,
            seed % 3 == 0 ? true : false
        );
        assertEq(
            context.ignoreAccountStatusCheck,
            seed % 4 == 0 ? true : false
        );
        assertEq(context.onBehalfOfAccount, account);
        assertEq(controllerEnabled, seed % 5 == 0 ? true : false);
    }
}
