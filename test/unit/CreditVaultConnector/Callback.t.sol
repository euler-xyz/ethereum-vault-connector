// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../cvc/CreditVaultConnectorHarness.sol";

contract CreditVaultConnectorHandler is CreditVaultConnectorHarness {
    using Set for SetStorage;

    function handlerCallback(
        address onBehalfOfAccount,
        uint value,
        bytes calldata data
    ) public payable returns (bytes memory result) {
        result = super.callback(onBehalfOfAccount, value, data);

        verifyVaultStatusChecks();
        verifyAccountStatusChecks();
    }
}

contract CallbackTest is Test {
    CreditVaultConnectorHandler internal cvc;

    event CallWithContext(
        address indexed caller,
        address indexed targetContract,
        address indexed onBehalfOfAccount,
        bytes4 selector
    );

    function setUp() public {
        cvc = new CreditVaultConnectorHandler();
    }

    fallback(bytes calldata data) external payable returns (bytes memory) {
        return data;
    }

    function revertEmptyTest() external pure {
        revert();
    }

    function test_Callback(
        address alice,
        bytes memory data,
        uint96 seed
    ) public {
        vm.assume(alice != address(0) && alice != address(cvc));
        address controller = address(new Vault(cvc));

        // first, test with a fallback function
        vm.deal(address(this), seed);
        vm.expectEmit(true, true, true, true, address(cvc));
        emit CallWithContext(address(this), address(this), alice, bytes4(data));
        bytes memory result = cvc.handlerCallback{value: seed}(
            alice,
            seed,
            data
        );
        assertEq(keccak256(result), keccak256(data));

        // then, test with a function selector
        vm.prank(alice);
        cvc.enableController(alice, controller);
        cvc.reset();
        Vault(controller).reset();

        data = abi.encodeWithSelector(
            Target(controller).callbackTest.selector,
            address(cvc),
            address(cvc),
            seed,
            alice
        );

        vm.deal(controller, seed);
        vm.expectEmit(true, true, true, true, address(cvc));
        emit CallWithContext(
            controller,
            controller,
            alice,
            Target.callbackTest.selector
        );
        vm.prank(controller);
        result = cvc.handlerCallback{value: seed}(alice, seed, data);
        assertEq(abi.decode(result, (uint)), seed);
    }

    function test_RevertIfDepthExceeded_Callback(address alice) external {
        vm.assume(alice != address(cvc));

        cvc.setCallDepth(10);

        vm.prank(alice);
        vm.expectRevert(ExecutionContext.CallDepthViolation.selector);
        cvc.callback(alice, 0, "");
    }

    function test_RevertIfChecksReentrancy_Callback(
        address alice,
        uint seed
    ) public {
        vm.assume(alice != address(cvc));

        cvc.setChecksLock(true);

        vm.deal(address(this), seed);
        vm.expectRevert(Errors.CVC_ChecksReentrancy.selector);
        cvc.callback{value: seed}(alice, seed, "");
    }

    function test_RevertIfImpersonateReentrancy_Callback(
        address alice,
        uint seed
    ) public {
        vm.assume(alice != address(cvc));

        cvc.setImpersonateLock(true);

        vm.deal(address(this), seed);
        vm.expectRevert(Errors.CVC_ImpersonateReentrancy.selector);
        cvc.callback{value: seed}(alice, seed, "");
    }

    function test_RevertIfMsgSenderNotAuthorized_Callback(
        address alice,
        uint seed
    ) public {
        vm.assume(alice != address(0));
        vm.assume(alice != address(cvc));

        // msg.sender is the CVC
        vm.deal(address(cvc), seed);
        vm.prank(address(cvc));
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.callback{value: seed}(alice, seed, "");
    }

    function test_RevertIfValueExceedsBalance_Call(
        address alice,
        uint128 seed
    ) public {
        vm.assume(alice != address(0) && alice != address(cvc));
        vm.assume(seed > 0);

        // reverts if value exceeds balance
        vm.deal(address(this), seed);
        vm.expectRevert(Errors.CVC_InvalidValue.selector);
        cvc.callback{value: seed - 1}(alice, seed, "");

        // succeeds if value does not exceed balance
        cvc.callback{value: seed}(alice, seed, "");
    }

    function test_RevertIfInternalCallIsUnsuccessful_Callback(
        address alice
    ) public {
        vm.assume(alice != address(0));
        vm.assume(alice != address(cvc));

        bytes memory data = abi.encodeWithSelector(
            this.revertEmptyTest.selector
        );

        vm.expectRevert(Errors.CVC_EmptyError.selector);
        cvc.callback(alice, 0, data);
    }
}
