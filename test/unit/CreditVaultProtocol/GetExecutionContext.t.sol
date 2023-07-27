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
        assertFalse(context.impersonateLock);
        assertEq(context.onBehalfOfAccount, address(0));
        assertFalse(controllerEnabled);

        if (seed % 2 == 0) {
            vm.prank(account);
            cvp.enableController(account, controller);
        }

        cvp.setBatchDepth(seed % 3 == 0 ? 2 : 1);
        cvp.setImpersonateLock(seed % 4 == 0 ? true : false);
        cvp.setOnBehalfOfAccount(account);

        (context, controllerEnabled) = cvp.getExecutionContext(controller);

        assertEq(context.batchDepth, seed % 3 == 0 ? 2 : 1);
        assertEq(
            context.impersonateLock,
            seed % 4 == 0 ? true : false
        );
        assertEq(context.onBehalfOfAccount, account);
        assertEq(controllerEnabled, seed % 2 == 0 ? true : false);
    }

    // for coverage
    function test_InvariantsCheck() external {
        cvp.invariantsCheck();
        cvp.reset();

        cvp.setBatchDepth(2);
        vm.expectRevert();
        cvp.invariantsCheck();
        cvp.reset();

        cvp.setChecksInProgressLock(true);
        vm.expectRevert();
        cvp.invariantsCheck();
        cvp.reset();

        cvp.setImpersonateLock(true);
        vm.expectRevert();
        cvp.invariantsCheck();
        cvp.reset();

        cvp.setOnBehalfOfAccount(address(1));
        vm.expectRevert();
        cvp.invariantsCheck();
        cvp.reset();

        cvp.setBatchDepth(2);
        cvp.requireAccountStatusCheck(address(1));
        vm.expectRevert();
        cvp.invariantsCheck();
        cvp.reset();

        cvp.setBatchDepth(2);
        cvp.requireAccountStatusCheck(address(0));
        vm.expectRevert();
        cvp.invariantsCheck();
        cvp.reset();

        cvp.setBatchDepth(2);
        cvp.requireVaultStatusCheck();
        vm.expectRevert();
        cvp.invariantsCheck();
        cvp.reset();

        cvp.setBatchDepth(2);
        vm.prank(address(0));
        cvp.requireVaultStatusCheck();
        vm.expectRevert();
        cvp.invariantsCheck();
        cvp.reset();
    }
}
