// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {BaseTest} from "../BaseTest.sol";
import {VaultAccountingIntegrityAssertion} from "../../src/VaultAccountingIntegrityAssertion.a.sol";
import {IEVC} from "../../../src/interfaces/IEthereumVaultConnector.sol";
import {IERC4626} from "openzeppelin-contracts/interfaces/IERC4626.sol";

// Import shared mocks
import {MockERC20} from "../mocks/MockERC20.sol";
import {MockEVault} from "../mocks/MockEVault.sol";
import {CashThiefVault} from "../mocks/MaliciousVaults.sol";
import {MockPerspective} from "../mocks/MockPerspective.sol";

/// @title TestVaultAccountingIntegrityAssertion
/// @notice Test suite for VaultAccountingIntegrityAssertion
/// @dev Tests the invariant: balance >= cash
contract TestVaultAccountingIntegrityAssertion is BaseTest {
    MockEVault public vault1;
    MockEVault public vault2;
    CashThiefVault public maliciousVault;
    MockERC20 public asset;
    MockPerspective public mockPerspective;

    /// @notice Helper to get assertion creation code with MockPerspective
    function getAssertionCreationCode() internal view returns (bytes memory) {
        address[] memory perspectives = new address[](1);
        perspectives[0] = address(mockPerspective);
        return abi.encodePacked(type(VaultAccountingIntegrityAssertion).creationCode, abi.encode(perspectives));
    }

    function setUp() public override {
        super.setUp();

        // Deploy MockPerspective FIRST
        mockPerspective = new MockPerspective();
        mockPerspective.setVerifyAll(false);

        // Deploy mock asset
        asset = new MockERC20("Mock Asset", "MOCK");

        // Deploy real vaults
        vault1 = new MockEVault(asset, evc);
        vault2 = new MockEVault(asset, evc);

        // Deploy malicious vault
        maliciousVault = new CashThiefVault(asset, evc);

        // Register vaults with the perspective
        mockPerspective.addVerifiedVault(address(vault1));
        mockPerspective.addVerifiedVault(address(vault2));
        mockPerspective.addVerifiedVault(address(maliciousVault));

        // Setup tokens (mint + approve)
        setupToken(asset, address(vault1), 1000e18);
        setupToken(asset, address(vault2), 1000e18);

        // Also approve malicious vault for user1
        vm.prank(user1);
        asset.approve(address(maliciousVault), type(uint256).max);
    }

    // ========================================
    // SUCCESS TESTS (balance >= cash maintained)
    // ========================================

    /// @notice SCENARIO: Normal deposit operation
    /// @dev After deposit: balance = cash, assertion passes
    function testAccountingIntegrity_Batch_NormalDeposit_Passes() public {
        // Create batch with deposit
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1);

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAccountingIntegrityAssertion.assertionBatchAccountingIntegrity.selector
        });

        // Execute batch call
        vm.prank(user1);
        evc.batch(items);

        // Assertion passes: balance (100e18) >= cash (100e18) ✓
    }

    /// @notice SCENARIO: Normal withdrawal operation
    /// @dev After withdrawal: balance = cash, assertion passes
    function testAccountingIntegrity_Batch_NormalWithdrawal_Passes() public {
        // Setup: Deposit first
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1));

        // Create batch with withdrawal
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.withdraw.selector, 50e18, user1, user1);

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAccountingIntegrityAssertion.assertionBatchAccountingIntegrity.selector
        });

        // Execute batch call
        vm.prank(user1);
        evc.batch(items);

        // Assertion passes: balance (50e18) >= cash (50e18) ✓
    }

    /// @notice SCENARIO: Normal borrow operation
    /// @dev After borrow: balance and cash both decrease, balance = cash, assertion passes
    function testAccountingIntegrity_Batch_NormalBorrow_Passes() public {
        // Setup: Deposit first
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1));

        // Create batch with borrow
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(MockEVault.borrow.selector, 30e18, user1);

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAccountingIntegrityAssertion.assertionBatchAccountingIntegrity.selector
        });

        // Execute batch call
        vm.prank(user1);
        evc.batch(items);

        // Assertion passes: balance (70e18) >= cash (70e18) ✓
    }

    /// @notice SCENARIO: Normal repay operation
    /// @dev After repay: balance and cash both increase, balance = cash, assertion passes
    function testAccountingIntegrity_Batch_NormalRepay_Passes() public {
        // Setup: Deposit and borrow first
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1));
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(MockEVault.borrow.selector, 30e18, user1));

        // Create batch with repay
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(MockEVault.repay.selector, 20e18, user1);

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAccountingIntegrityAssertion.assertionBatchAccountingIntegrity.selector
        });

        // Execute batch call
        vm.prank(user1);
        evc.batch(items);

        // Assertion passes: balance (90e18) >= cash (90e18) ✓
    }

    /// @notice SCENARIO: Multiple operations in single batch
    /// @dev All operations maintain balance >= cash
    function testAccountingIntegrity_Batch_MultipleOperations_Passes() public {
        // Setup: Deposit first
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 200e18, user1));

        // Create batch with: withdraw 50, borrow 30, deposit 20
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](3);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.withdraw.selector, 50e18, user1, user1);

        items[1].targetContract = address(vault1);
        items[1].onBehalfOfAccount = user1;
        items[1].value = 0;
        items[1].data = abi.encodeWithSelector(MockEVault.borrow.selector, 30e18, user1);

        items[2].targetContract = address(vault1);
        items[2].onBehalfOfAccount = user1;
        items[2].value = 0;
        items[2].data = abi.encodeWithSelector(IERC4626.deposit.selector, 20e18, user1);

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAccountingIntegrityAssertion.assertionBatchAccountingIntegrity.selector
        });

        // Execute batch call
        vm.prank(user1);
        evc.batch(items);

        // Assertion passes: balance (140e18) >= cash (140e18) ✓
        // (200 - 50 - 30 + 20 = 140)
    }

    /// @notice SCENARIO: Operations on multiple vaults
    /// @dev Each vault independently maintains balance >= cash
    function testAccountingIntegrity_Batch_MultipleVaults_Passes() public {
        // Create batch with deposits to both vaults
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](2);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1);

        items[1].targetContract = address(vault2);
        items[1].onBehalfOfAccount = user1;
        items[1].value = 0;
        items[1].data = abi.encodeWithSelector(IERC4626.deposit.selector, 50e18, user1);

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAccountingIntegrityAssertion.assertionBatchAccountingIntegrity.selector
        });

        // Execute batch call
        vm.prank(user1);
        evc.batch(items);

        // Assertion passes for both vaults ✓
    }

    /// @notice SCENARIO: EVC.call() operation
    /// @dev Tests assertion works with call() not just batch()
    function testAccountingIntegrity_Call_NormalWithdrawal_Passes() public {
        // Setup: Deposit first
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1));

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAccountingIntegrityAssertion.assertionCallAccountingIntegrity.selector
        });

        // Execute call with withdrawal
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.withdraw.selector, 50e18, user1, user1));

        // Assertion passes ✓
    }

    /// @notice SCENARIO: EVC.controlCollateral() during liquidation
    /// @dev Tests assertion works with controlCollateral (no asset movement, just share transfer)
    function testAccountingIntegrity_ControlCollateral_ShareTransfer_Passes() public {
        // Setup: Enable controller and collateral
        vm.startPrank(user1);
        evc.enableController(user1, address(vault1));
        evc.enableCollateral(user1, address(vault2));
        vm.stopPrank();

        // Deposit collateral into vault2
        vm.prank(user1);
        evc.call(address(vault2), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1));

        // Register assertion for controlCollateral operations
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAccountingIntegrityAssertion.assertionControlCollateralAccountingIntegrity.selector
        });

        // Execute controlCollateral - just transfers shares, no asset movement
        vm.prank(address(vault1));
        evc.controlCollateral(
            address(vault2), user1, 0, abi.encodeWithSelector(MockEVault.seizeCollateral.selector, user1, user2, 50e18)
        );

        // Assertion passes: no asset movement, balance and cash unchanged ✓
    }

    /// @notice SCENARIO: Zero amount operations
    /// @dev No spurious failures on zero-amount operations
    function testAccountingIntegrity_Batch_ZeroAmount_Passes() public {
        // Create batch with zero deposit
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.deposit.selector, 0, user1);

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAccountingIntegrityAssertion.assertionBatchAccountingIntegrity.selector
        });

        // Execute batch call
        vm.prank(user1);
        evc.batch(items);

        // Assertion passes: balance (0) >= cash (0) ✓
    }

    // ========================================
    // FAILURE TESTS (balance < cash violated)
    // ========================================

    /// @notice SCENARIO: Malicious withdrawal steals assets without updating cash
    /// @dev Vault transfers extra assets, balance < cash after
    function testAccountingIntegrity_Batch_StealWithoutCashUpdate_Fails() public {
        // Setup: Deposit into malicious vault
        vm.prank(user1);
        evc.call(address(maliciousVault), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1));

        // Enable theft behavior
        maliciousVault.setStealOnWithdraw(true);

        // Create batch with withdrawal (will steal 10e18 extra)
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(maliciousVault);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.withdraw.selector, 50e18, user1, user1);

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAccountingIntegrityAssertion.assertionBatchAccountingIntegrity.selector
        });

        // Execute batch call - should fail assertion
        // After: balance = 40e18 (100 - 50 - 10 stolen), cash = 50e18 (100 - 50)
        // 40 < 50, assertion fails ✗
        vm.prank(user1);
        vm.expectRevert("VaultAccountingIntegrityAssertion: Balance < cash");
        evc.batch(items);
    }

    /// @notice SCENARIO: Malicious withdrawal that fails to decrement cash
    /// @dev Vault transfers assets but leaves cash unchanged
    function testAccountingIntegrity_Batch_WithdrawWithoutCashUpdate_Fails() public {
        // Setup: Deposit into malicious vault
        vm.prank(user1);
        evc.call(address(maliciousVault), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1));

        // Enable skip cash update behavior
        maliciousVault.setSkipCashUpdate(true);

        // Create batch with withdrawal (won't update cash)
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(maliciousVault);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.withdraw.selector, 50e18, user1, user1);

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAccountingIntegrityAssertion.assertionBatchAccountingIntegrity.selector
        });

        // Execute batch call - should fail assertion
        // After: balance = 50e18 (100 - 50), cash = 100e18 (unchanged)
        // 50 < 100, assertion fails ✗
        vm.prank(user1);
        vm.expectRevert("VaultAccountingIntegrityAssertion: Balance < cash");
        evc.batch(items);
    }

    /// @notice SCENARIO: Vault in bad state - cash manually inflated
    /// @dev Cash is set higher than balance
    function testAccountingIntegrity_Batch_BalanceLessThanCash_Fails() public {
        // Setup: Deposit first
        vm.prank(user1);
        evc.call(address(maliciousVault), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1));

        // Manually corrupt the vault state: inflate cash
        maliciousVault.corruptCash(150e18);

        // Try any operation - should fail check immediately
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(maliciousVault);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.deposit.selector, 10e18, user1);

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAccountingIntegrityAssertion.assertionBatchAccountingIntegrity.selector
        });

        // Execute batch call - should fail
        // Before operation: balance = 100e18, cash = 150e18
        // 100 < 150, assertion fails ✗
        vm.prank(user1);
        vm.expectRevert("VaultAccountingIntegrityAssertion: Balance < cash");
        evc.batch(items);
    }

    /// @notice SCENARIO: Gas benchmark with 5 operations
    /// @dev Tests assertion performance
    function testAccountingIntegrity_Batch_5Operations_Passes() public {
        // Setup: Mint more tokens for multiple deposits
        asset.mint(user1, 1000e18);
        vm.prank(user1);
        asset.approve(address(vault1), type(uint256).max);

        // Create batch with 5 deposits
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](5);
        for (uint256 i = 0; i < 5; i++) {
            items[i].targetContract = address(vault1);
            items[i].onBehalfOfAccount = user1;
            items[i].value = 0;
            items[i].data = abi.encodeWithSelector(IERC4626.deposit.selector, 10e18, user1);
        }

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAccountingIntegrityAssertion.assertionBatchAccountingIntegrity.selector
        });

        vm.prank(user1);
        evc.batch(items);
    }

    /// @notice SCENARIO: Batch with 10 deposit operations - gas benchmark
    /// @dev Tests assertion performance with large batch size
    function testAccountingIntegrity_Batch_10Operations_Passes() public {
        // Setup: Mint more tokens for multiple deposits
        asset.mint(user1, 2000e18);
        vm.prank(user1);
        asset.approve(address(vault1), type(uint256).max);

        // Create batch with 10 deposits
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](10);
        for (uint256 i = 0; i < 10; i++) {
            items[i].targetContract = address(vault1);
            items[i].onBehalfOfAccount = user1;
            items[i].value = 0;
            items[i].data = abi.encodeWithSelector(IERC4626.deposit.selector, 10e18, user1);
        }

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAccountingIntegrityAssertion.assertionBatchAccountingIntegrity.selector
        });

        vm.prank(user1);
        evc.batch(items);
    }

    // ========================================
    // BOUNDARY CONDITION TESTS
    // ========================================

    /// @notice SCENARIO: Vault with max uint256 cash value - should handle gracefully
    /// @dev Tests boundary condition with maximum possible cash value
    ///
    /// TEST SETUP:
    /// - Vault has very large cash value (near uint256 max)
    /// - User performs a withdrawal
    /// - Invariant: balance >= cash should still hold
    ///
    /// EXPECTED RESULT: Assertion should PASS (handles large values correctly)
    /// NOTE: We use a large but safe value (uint256.max / 2) to avoid overflow in arithmetic
    function testVaultAccountingIntegrity_MaxUint256Cash_Passes() public {
        // Setup: Enable vault1 as controller for user1
        vm.prank(user1);
        evc.enableController(user1, address(vault1));

        // Mint a very large amount to user1 (half of max to avoid overflows)
        uint256 largeAmount = type(uint256).max / 2;
        asset.mint(user1, largeAmount);

        // User1 deposits the large amount
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, largeAmount, user1));

        // Verify vault has large cash value
        uint256 vaultCash = vault1.cash();
        assertGt(vaultCash, 1e70, "Vault should have very large cash value");

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAccountingIntegrityAssertion.assertionCallAccountingIntegrity.selector
        });

        // User1 withdraws a small amount
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.withdraw.selector, 100e18, user1, user1));

        // Assertion should pass - invariant balance >= cash holds even with max values
    }
}
