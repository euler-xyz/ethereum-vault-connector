// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../evc/EthereumVaultConnectorHarness.sol";

contract EthereumVaultConnectorHandler is EthereumVaultConnectorHarness {
    using Set for SetStorage;

    function handlerCall(
        address targetContract,
        address onBehalfOfAccount,
        uint256 value,
        bytes calldata data
    ) public payable returns (bytes memory result) {
        result = super.call(targetContract, onBehalfOfAccount, value, data);

        verifyVaultStatusChecks();
        verifyAccountStatusChecks();
    }
}

contract CallTest is Test {
    EthereumVaultConnectorHandler internal evc;

    event CallWithContext(
        address indexed caller, address indexed targetContract, address indexed onBehalfOfAccount, bytes4 selector
    );

    function setUp() public {
        evc = new EthereumVaultConnectorHandler();
    }

    function test_Call(address alice, uint96 seed) public {
        vm.assume(alice != address(0) && alice != address(evc));

        address account;
        if (seed % 2 == 0) {
            // in this case the account is not alice's sub-account thus alice must be an operator
            account = address(uint160(alice) ^ 256);
            vm.prank(account);
            evc.setAccountOperator(account, alice, true);
        } else {
            // in this case the account is alice's sub-account
            account = address(uint160(alice) ^ (seed % 256));
        }
        vm.assume(account != address(0));

        address targetContract = address(new Target());
        address nestedTargetContract = address(new TargetWithNesting());
        address controller = address(new Vault(evc));
        vm.assume(
            targetContract != alice && targetContract != address(evc) && !evc.haveCommonOwner(targetContract, alice)
                && !evc.haveCommonOwner(targetContract, account)
        );
        vm.assume(
            nestedTargetContract != alice && nestedTargetContract != address(evc)
                && !evc.haveCommonOwner(nestedTargetContract, alice) && !evc.haveCommonOwner(nestedTargetContract, account)
        );

        vm.prank(alice);
        evc.enableController(account, controller);
        evc.reset();
        Vault(controller).reset();

        bytes memory data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector, address(evc), address(evc), seed, account, seed % 2 == 0
        );

        vm.deal(alice, seed);
        vm.expectEmit(true, true, true, true, address(evc));
        emit CallWithContext(alice, targetContract, account, Target.callTest.selector);
        vm.prank(alice);
        bytes memory result = evc.handlerCall{value: seed}(targetContract, account, seed, data);
        assertEq(abi.decode(result, (uint256)), seed);

        evc.reset();
        Vault(controller).reset();

        // on behalf of account should be correct in a nested call as well
        data = abi.encodeWithSelector(
            TargetWithNesting(nestedTargetContract).nestedCallTest.selector,
            address(evc),
            address(evc),
            targetContract,
            seed,
            account,
            seed % 2 == 0
        );

        vm.deal(alice, seed);
        vm.expectEmit(true, true, true, true, address(evc));
        emit CallWithContext(alice, nestedTargetContract, account, TargetWithNesting.nestedCallTest.selector);
        vm.expectEmit(true, true, true, true, address(evc));
        emit CallWithContext(nestedTargetContract, targetContract, nestedTargetContract, Target.callTest.selector);
        vm.prank(alice);
        result = evc.handlerCall{value: seed}(nestedTargetContract, account, seed, data);
        assertEq(abi.decode(result, (uint256)), seed);
    }

    function test_RevertIfDepthExceeded_Call(address alice) external {
        vm.assume(alice != address(0) && alice != address(evc));

        evc.setCallDepth(10);

        vm.prank(alice);
        vm.expectRevert(ExecutionContext.CallDepthViolation.selector);
        evc.call(address(0), alice, 0, "");
    }

    function test_RevertIfNotOwnerOrOperator_Call(address alice, address bob, uint256 seed) public {
        vm.assume(alice != address(0) && alice != address(evc));
        vm.assume(!evc.haveCommonOwner(alice, bob));
        vm.assume(bob != address(0));

        address targetContract = address(new Target());
        vm.assume(targetContract != alice && targetContract != address(evc));

        bytes memory data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector, address(evc), address(evc), seed, alice, false
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(Errors.EVC_NotAuthorized.selector);
        evc.call{value: seed}(targetContract, bob, seed, data);
    }

    function test_RevertIfChecksReentrancy_Call(address alice, uint256 seed) public {
        vm.assume(alice != address(evc));

        address targetContract = address(new Target());
        vm.assume(targetContract != alice && targetContract != address(evc));

        evc.setChecksLock(true);

        bytes memory data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector, address(evc), address(evc), seed, alice, false
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(Errors.EVC_ChecksReentrancy.selector);
        evc.call{value: seed}(targetContract, alice, seed, data);
    }

    function test_RevertIfImpersonateReentrancy_Call(address alice, uint256 seed) public {
        vm.assume(alice != address(evc));

        address targetContract = address(new Target());
        vm.assume(targetContract != alice && targetContract != address(evc));

        evc.setImpersonateLock(true);

        bytes memory data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector, address(evc), address(evc), seed, alice, false
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(Errors.EVC_ImpersonateReentrancy.selector);
        evc.call{value: seed}(targetContract, alice, seed, data);
    }

    function test_RevertIfTargetContractInvalid_Call(address alice, uint256 seed) public {
        // call setUp() explicitly for Diligence Fuzzing tool to pass
        setUp();

        vm.assume(alice != address(0));
        vm.assume(alice != address(evc));

        // target contract is the EVC
        address targetContract = address(evc);
        bytes memory data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector, address(evc), targetContract, seed, alice, false
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(Errors.EVC_InvalidAddress.selector);
        evc.call{value: seed}(targetContract, alice, seed, data);

        // target contract is the msg.sender
        targetContract = address(this);
        data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector, address(evc), address(evc), seed, address(this), false
        );

        vm.deal(address(this), seed);
        vm.expectRevert(Errors.EVC_InvalidAddress.selector);
        evc.call{value: seed}(targetContract, address(this), seed, data);

        // target contract is the ERC1820 registry
        targetContract = 0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24;
        data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector, address(evc), address(evc), seed, alice, false
        );

        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(Errors.EVC_InvalidAddress.selector);
        evc.call{value: seed}(targetContract, alice, seed, data);
    }

    function test_RevertIfValueExceedsBalance_Call(address alice, uint128 seed) public {
        vm.assume(alice != address(0) && alice != address(evc));
        vm.assume(seed > 0);

        address targetContract = address(new Target());
        vm.assume(targetContract != alice && targetContract != address(evc));

        bytes memory data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector, address(evc), address(evc), seed, alice, false
        );

        // reverts if value exceeds balance
        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(Errors.EVC_InvalidValue.selector);
        evc.call{value: seed - 1}(targetContract, alice, seed, data);

        // succeeds if value does not exceed balance
        vm.prank(alice);
        evc.call{value: seed}(targetContract, alice, seed, data);
    }

    function test_RevertIfInternalCallIsUnsuccessful_Call(address alice) public {
        // call setUp() explicitly for Diligence Fuzzing tool to pass
        setUp();

        vm.assume(alice != address(0));
        vm.assume(alice != address(evc));

        address targetContract = address(new Target());
        vm.assume(targetContract != alice && targetContract != address(evc));

        bytes memory data = abi.encodeWithSelector(Target(targetContract).revertEmptyTest.selector);

        vm.prank(alice);
        vm.expectRevert(Errors.EVC_EmptyError.selector);
        evc.call(targetContract, alice, 0, data);
    }
}
