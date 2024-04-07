// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../../evc/EthereumVaultConnectorHarness.sol";

contract ReceiveTest is Test {
    EthereumVaultConnectorHarness internal evc;

    function setUp() public {
        evc = new EthereumVaultConnectorHarness();
    }

    function test_Receive(uint64 value) external {
        vm.assume(value > 0);
        vm.deal(address(this), 2 * uint256(value));

        // succeds when checks are not deferred
        address(evc).call{value: value}("");

        evc.setChecksDeferred(true);
        vm.expectRevert(Errors.EVC_NotAuthorized.selector);
        address(evc).call{value: value}("");
    }
}
