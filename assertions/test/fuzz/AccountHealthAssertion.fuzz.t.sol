// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {BaseTest} from "../BaseTest.sol";
import {AccountHealthAssertion} from "../../src/AccountHealthAssertion.a.sol";
import {IEVC} from "../../../src/interfaces/IEthereumVaultConnector.sol";
import {MockERC20} from "../mocks/MockERC20.sol";
import {MockVault} from "../mocks/MockVault.sol";
import {MockEVault} from "../mocks/MockEVault.sol";
import {MockPerspective} from "../mocks/MockPerspective.sol";

/// @title AccountHealthAssertion Fuzz Tests
/// @notice Fuzz testing for critical AccountHealthAssertion scenarios
/// @dev Property-based testing to verify account health invariants hold across parameter ranges
contract AccountHealthAssertionFuzzTest is BaseTest {
    AccountHealthAssertion public assertion;

    // Test vaults
    MockVault public vault1; // Borrowing vault
    MockVault public vault2; // Collateral vault

    // Test tokens
    MockERC20 public token1;
    MockERC20 public token2;
    MockERC20 public asset;

    // Mock perspective for vault verification
    MockPerspective public mockPerspective;

    /// @notice Helper to get assertion creation code with MockPerspective
    function getAssertionCreationCode() internal view returns (bytes memory) {
        address[] memory perspectives = new address[](1);
        perspectives[0] = address(mockPerspective);
        return abi.encodePacked(type(AccountHealthAssertion).creationCode, abi.encode(perspectives));
    }

    function setUp() public override {
        super.setUp();

        // Deploy MockPerspective FIRST
        mockPerspective = new MockPerspective();
        mockPerspective.setVerifyAll(false);

        // Deploy test tokens
        token1 = new MockERC20("Test Token 1", "TT1");
        token2 = new MockERC20("Test Token 2", "TT2");
        asset = new MockERC20("Test Asset", "TA");

        // Deploy test vaults
        vault1 = new MockVault(address(evc), address(token1));
        vault2 = new MockVault(address(evc), address(token2));

        // Register vaults with perspective
        mockPerspective.addVerifiedVault(address(vault1));
        mockPerspective.addVerifiedVault(address(vault2));

        // Deploy assertion with perspective
        address[] memory perspectives = new address[](1);
        perspectives[0] = address(mockPerspective);
        assertion = new AccountHealthAssertion(perspectives);

        // Setup test environment
        setupUserETH();

        // Setup tokens (mint + approve)
        setupToken(token1, address(vault1), 1000000e18);
        setupToken(token2, address(vault2), 1000000e18);
    }

    /// @notice Fuzz test: Healthy borrow operations should always pass
    /// @dev Tests the invariant that borrowing within collateral limits maintains health
    /// @param borrowAmount Amount to borrow (bounded to realistic range)
    /// @param collateralAmount Amount of collateral (bounded to >= borrowAmount)
    function testFuzz_HealthyBorrow(
        uint256 borrowAmount,
        uint256 collateralAmount
    ) public {
        // Bound inputs to realistic ranges
        borrowAmount = bound(borrowAmount, 1e18, 1000e18);
        collateralAmount = bound(collateralAmount, borrowAmount, 10000e18);

        // Ensure collateral >= borrow (healthy condition)
        vm.assume(collateralAmount >= borrowAmount);

        // Setup: Enable collateral and controller
        vm.startPrank(user1);
        evc.enableController(user1, address(vault1));
        evc.enableCollateral(user1, address(vault2));
        vm.stopPrank();

        // Deposit liquidity in vault1 so there's funds to borrow
        vm.prank(user2);
        evc.call(
            address(vault1), user2, 0, abi.encodeWithSelector(MockVault.deposit.selector, collateralAmount * 2, user2)
        );

        // Deposit collateral in vault2
        IEVC.BatchItem[] memory setupItems = new IEVC.BatchItem[](1);
        setupItems[0].targetContract = address(vault2);
        setupItems[0].onBehalfOfAccount = user1;
        setupItems[0].value = 0;
        setupItems[0].data = abi.encodeWithSelector(MockVault.deposit.selector, collateralAmount, user1);

        vm.prank(user1);
        evc.batch(setupItems);

        // Register assertion BEFORE the borrow operation
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: AccountHealthAssertion.assertionBatchAccountHealth.selector
        });

        // Create batch call for borrow
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(MockVault.borrow.selector, borrowAmount, user1);

        // Execute batch call - should PASS (healthy borrow)
        vm.prank(user1);
        evc.batch(items);

        // Assertion should pass - account remains healthy after safe borrow
    }

    /// @notice Fuzz test: Transitions from healthy to unhealthy should always revert
    /// @dev Tests the invariant that operations making accounts unhealthy are rejected
    /// @param initialDebt Initial debt amount (bounded)
    /// @param extraDebt Additional debt that will cause unhealthy state (bounded)
    /// @param collateral Collateral amount (bounded to create transition scenario)
    function testFuzz_HealthyBecomesUnhealthy(
        uint256 initialDebt,
        uint256 extraDebt,
        uint256 collateral
    ) public {
        // Bound inputs to realistic ranges
        initialDebt = bound(initialDebt, 1e18, 100e18);
        extraDebt = bound(extraDebt, 1e18, 100e18);
        collateral = bound(collateral, 50e18, 150e18);

        // Ensure starts healthy: collateral >= initialDebt
        vm.assume(collateral >= initialDebt);

        // Ensure ends unhealthy: collateral < initialDebt + extraDebt (doubled by mock)
        // MockVault with breakHealthInvariant flag doubles the debt increase
        vm.assume(collateral < initialDebt + (extraDebt * 2));

        // Setup: Enable collateral and controller
        vm.startPrank(user1);
        evc.enableController(user1, address(vault1));
        evc.enableCollateral(user1, address(vault2));
        vm.stopPrank();

        // Deposit liquidity in vault1
        vm.prank(user2);
        evc.call(address(vault1), user2, 0, abi.encodeWithSelector(MockVault.deposit.selector, collateral * 3, user2));

        // Create healthy position: deposit collateral and initial debt
        IEVC.BatchItem[] memory setupItems = new IEVC.BatchItem[](2);
        setupItems[0].targetContract = address(vault2);
        setupItems[0].onBehalfOfAccount = user1;
        setupItems[0].value = 0;
        setupItems[0].data = abi.encodeWithSelector(MockVault.deposit.selector, collateral, user1);

        setupItems[1].targetContract = address(vault1);
        setupItems[1].onBehalfOfAccount = user1;
        setupItems[1].value = 0;
        setupItems[1].data = abi.encodeWithSelector(MockVault.borrow.selector, initialDebt, user1);

        vm.prank(user1);
        evc.batch(setupItems);

        // Set flag to break health invariant (doubles liability increase)
        vault1.setBreakHealthInvariant(true);

        // Register assertion BEFORE the operation that breaks health
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: AccountHealthAssertion.assertionBatchAccountHealth.selector
        });

        // Create batch call that will break health
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(MockVault.borrow.selector, extraDebt, user1);

        // Execute batch call - should REVERT (became unhealthy)
        vm.prank(user1);
        vm.expectRevert("AccountHealthAssertion: Healthy account became unhealthy");
        evc.batch(items);
    }

    /// @notice Fuzz test: Account health should improve during debt repayment
    /// @dev Tests that healthy accounts remain healthy when repaying debt
    /// @param initialCollateral Amount of initial collateral (bounded)
    /// @param borrowAmount Amount to borrow (bounded to keep account healthy)
    /// @param repayAmount Amount of debt to repay (bounded)
    function testFuzz_HealthyDebtRepayment(
        uint256 initialCollateral,
        uint256 borrowAmount,
        uint256 repayAmount
    ) public {
        // Bound inputs to realistic ranges
        initialCollateral = bound(initialCollateral, 100e18, 500e18);
        borrowAmount = bound(borrowAmount, 10e18, 100e18);
        repayAmount = bound(repayAmount, 1e18, 50e18);

        // Ensure account starts healthy: initialCollateral >= borrowAmount
        vm.assume(initialCollateral >= borrowAmount);

        // Ensure repayment amount is reasonable (can't repay more than borrowed)
        vm.assume(repayAmount <= borrowAmount);

        // Setup: Enable controller and collateral
        vm.startPrank(user1);
        evc.enableController(user1, address(vault1));
        evc.enableCollateral(user1, address(vault2));
        vm.stopPrank();

        // Deposit liquidity in vault1 for borrowing
        vm.prank(user2);
        evc.call(
            address(vault1), user2, 0, abi.encodeWithSelector(MockVault.deposit.selector, borrowAmount * 10, user2)
        );

        // Create healthy position: deposit collateral and borrow
        IEVC.BatchItem[] memory setupItems = new IEVC.BatchItem[](2);
        setupItems[0].targetContract = address(vault2);
        setupItems[0].onBehalfOfAccount = user1;
        setupItems[0].value = 0;
        setupItems[0].data = abi.encodeWithSelector(MockVault.deposit.selector, initialCollateral, user1);

        setupItems[1].targetContract = address(vault1);
        setupItems[1].onBehalfOfAccount = user1;
        setupItems[1].value = 0;
        setupItems[1].data = abi.encodeWithSelector(MockVault.borrow.selector, borrowAmount, user1);

        vm.prank(user1);
        evc.batch(setupItems);

        // Register assertion BEFORE debt repayment
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: AccountHealthAssertion.assertionBatchAccountHealth.selector
        });

        // Repay some debt (improves health) - should PASS
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(MockVault.repay.selector, repayAmount, user1);

        vm.prank(user1);
        evc.batch(items);

        // Assertion should pass - account health improved (less debt)
    }
}
