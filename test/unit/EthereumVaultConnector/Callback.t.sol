// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../../evc/EthereumVaultConnectorHarness.sol";

contract EthereumVaultConnectorHandler is EthereumVaultConnectorHarness {
    using Set for SetStorage;

    function handlerCallback(
        address onBehalfOfAccount,
        uint256 value,
        bytes calldata data
    ) public payable returns (bytes memory result) {
        result = super.callback(onBehalfOfAccount, value, data);

        verifyVaultStatusChecks();
        verifyAccountStatusChecks();
    }
}

contract CallbackTest is Test {
    EthereumVaultConnectorHandler internal evc;

    event CallWithContext(
        address indexed caller, address indexed targetContract, address indexed onBehalfOfAccount, bytes4 selector
    );

    function setUp() public {
        evc = new EthereumVaultConnectorHandler();
    }

    fallback(bytes calldata data) external payable returns (bytes memory) {
        return data;
    }

    function revertEmptyTest() external pure {
        revert();
    }

    function test_Callback(address alice, bytes memory data, uint96 seed) public {
        vm.assume(alice != address(0) && alice != address(evc));
        address controller = address(new Vault(evc));

        // first, test with a fallback function
        vm.deal(address(this), seed);
        vm.expectEmit(true, true, true, true, address(evc));
        emit CallWithContext(address(this), address(this), alice, bytes4(data));
        bytes memory result = evc.handlerCallback{value: seed}(alice, seed, data);
        assertEq(keccak256(result), keccak256(data));

        // then, test with a function selector
        vm.prank(alice);
        evc.enableController(alice, controller);
        evc.reset();
        Vault(controller).reset();

        data = abi.encodeWithSelector(Target(controller).callbackTest.selector, address(evc), address(evc), seed, alice);

        vm.deal(controller, seed);
        vm.expectEmit(true, true, true, true, address(evc));
        emit CallWithContext(controller, controller, alice, Target.callbackTest.selector);
        vm.prank(controller);
        result = evc.handlerCallback{value: seed}(alice, seed, data);
        assertEq(abi.decode(result, (uint256)), seed);
    }

    function test_RevertIfDepthExceeded_Callback(address alice) external {
        vm.assume(alice != address(evc));

        evc.setCallDepth(10);

        vm.prank(alice);
        vm.expectRevert(ExecutionContext.CallDepthViolation.selector);
        evc.callback(alice, 0, "");
    }

    function test_RevertIfChecksReentrancy_Callback(address alice, uint256 seed) public {
        vm.assume(alice != address(evc));

        evc.setChecksLock(true);

        vm.deal(address(this), seed);
        vm.expectRevert(Errors.EVC_ChecksReentrancy.selector);
        evc.callback{value: seed}(alice, seed, "");
    }

    function test_RevertIfImpersonateReentrancy_Callback(address alice, uint256 seed) public {
        vm.assume(alice != address(evc));

        evc.setImpersonateLock(true);

        vm.deal(address(this), seed);
        vm.expectRevert(Errors.EVC_ImpersonateReentrancy.selector);
        evc.callback{value: seed}(alice, seed, "");
    }

    function test_RevertIfMsgSenderNotAuthorized_Callback(address alice, uint256 seed) public {
        vm.assume(alice != address(0));
        vm.assume(alice != address(evc));

        // msg.sender is the EVC
        vm.deal(address(evc), seed);
        vm.prank(address(evc));
        vm.expectRevert(Errors.EVC_NotAuthorized.selector);
        evc.callback{value: seed}(alice, seed, "");
    }

    function test_RevertIfValueExceedsBalance_Call(address alice, uint128 seed) public {
        vm.assume(alice != address(0) && alice != address(evc));
        vm.assume(seed > 0);

        // reverts if value exceeds balance
        vm.deal(address(this), seed);
        vm.expectRevert(Errors.EVC_InvalidValue.selector);
        evc.callback{value: seed - 1}(alice, seed, "");

        // succeeds if value does not exceed balance
        evc.callback{value: seed}(alice, seed, "");
    }

    function test_RevertIfInternalCallIsUnsuccessful_Callback(address alice) public {
        vm.assume(alice != address(0));
        vm.assume(alice != address(evc));

        bytes memory data = abi.encodeWithSelector(this.revertEmptyTest.selector);

        vm.expectRevert(Errors.EVC_EmptyError.selector);
        evc.callback(alice, 0, data);
    }
}
