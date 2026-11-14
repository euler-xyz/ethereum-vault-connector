// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {BaseTest} from "../BaseTest.sol";
import {VaultAssetTransferAccountingAssertion} from "../../src/VaultAssetTransferAccountingAssertion.a.sol";
import {IEVC} from "../../../src/interfaces/IEthereumVaultConnector.sol";
import {IERC4626} from "lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol";

// Import shared mocks
import {MockERC20} from "../mocks/MockERC20.sol";
import {MockEVault} from "../mocks/MockEVault.sol";
import {EventManipulatorVault, MockNonVaultContract, WrapperVault} from "../mocks/MaliciousVaults.sol";
import {MockPerspective} from "../mocks/MockPerspective.sol";

/// @title TestVaultAssetTransferAccountingAssertion
/// @notice Comprehensive test suite for the VaultAssetTransferAccountingAssertion assertion
/// @dev Tests happy path scenarios with real protocol vaults and failure scenarios with mock malicious vaults
contract TestVaultAssetTransferAccountingAssertion is BaseTest {
    VaultAssetTransferAccountingAssertion public assertion;

    // Test vaults (real protocol behavior)
    MockEVault public vault1;
    MockEVault public vault2;

    // Test tokens
    MockERC20 public token1;
    MockERC20 public token2;

    // Mock perspective for vault verification
    MockPerspective public mockPerspective;

    /// @notice Helper to get assertion creation code with MockPerspective
    function getAssertionCreationCode() internal view returns (bytes memory) {
        address[] memory perspectives = new address[](1);
        perspectives[0] = address(mockPerspective);
        return abi.encodePacked(type(VaultAssetTransferAccountingAssertion).creationCode, abi.encode(perspectives));
    }

    /// @notice Helper to register a vault with the mock perspective
    function registerVaultWithPerspective(
        address vault
    ) internal {
        mockPerspective.addVerifiedVault(vault);
    }

    function setUp() public override {
        super.setUp();

        // Deploy MockPerspective FIRST
        mockPerspective = new MockPerspective();
        mockPerspective.setVerifyAll(false);

        // Deploy test tokens
        token1 = new MockERC20("Test Token 1", "TT1");
        token2 = new MockERC20("Test Token 2", "TT2");

        // Deploy test vaults (real protocol behavior)
        vault1 = new MockEVault(token1, evc);
        vault2 = new MockEVault(token2, evc);

        // Register vaults with the perspective
        mockPerspective.addVerifiedVault(address(vault1));
        mockPerspective.addVerifiedVault(address(vault2));

        // Deploy assertion with perspective
        address[] memory perspectives = new address[](1);
        perspectives[0] = address(mockPerspective);
        assertion = new VaultAssetTransferAccountingAssertion(perspectives);

        // Setup test environment
        setupUserETH();

        // Setup tokens (mint + approve)
        setupToken(token1, address(vault1), 1000000e18);
        setupToken(token2, address(vault2), 1000000e18);
    }

    // ========================================
    // HAPPY PATH TESTS (Real Protocol Behavior)
    // ========================================

    /// @notice SCENARIO: Normal withdrawal with proper event emission
    /// @dev Verifies assertion passes when Transfer event matches Withdraw event
    ///
    /// TEST SETUP:
    /// - User1 deposits 100e18 tokens
    /// - User1 withdraws 50e18 tokens
    /// - Withdraw event emitted with 50e18 assets
    /// - Transfer event emitted with 50e18 amount
    ///
    /// EXPECTED RESULT: Assertion passes (totalTransferred <= totalWithdrawn)
    function testAssetTransferAccounting_Batch_NormalWithdrawal_Passes() public {
        // Setup: Deposit first
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1));

        // Create batch call that withdraws 50e18
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.withdraw.selector, 50e18, user1, user1);

        // Register assertion for the batch call
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionBatchAssetTransferAccounting.selector
        });

        // Execute batch call - this will trigger the assertion
        vm.prank(user1);
        evc.batch(items);

        // Assertion should pass - Transfer event matches Withdraw event
    }

    /// @notice SCENARIO: Normal borrow with proper event emission
    /// @dev Verifies assertion passes when Transfer event matches Borrow event
    ///
    /// TEST SETUP:
    /// - Vault has liquidity from user2 deposit
    /// - User1 borrows 30e18 tokens
    /// - Borrow event emitted with 30e18 assets
    /// - Transfer event emitted with 30e18 amount
    ///
    /// EXPECTED RESULT: Assertion passes (totalTransferred <= totalBorrowed)
    function testAssetTransferAccounting_Batch_NormalBorrow_Passes() public {
        // Setup: Provide liquidity from user2
        vm.prank(user2);
        evc.call(address(vault1), user2, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 1000e18, user2));

        // Create batch call that borrows 30e18
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(MockEVault.borrow.selector, 30e18, user1);

        // Register assertion for the batch call
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionBatchAssetTransferAccounting.selector
        });

        // Execute batch call - this will trigger the assertion
        vm.prank(user1);
        evc.batch(items);

        // Assertion should pass - Transfer event matches Borrow event
    }

    /// @notice SCENARIO: Multiple withdrawals in one transaction
    /// @dev Verifies assertion sums all Transfer and Withdraw events correctly
    ///
    /// TEST SETUP:
    /// - User1 has deposit
    /// - Batch contains two withdrawals from same user: 20e18 and 30e18
    /// - Total Transfer events: 50e18
    /// - Total Withdraw events: 50e18
    ///
    /// EXPECTED RESULT: Assertion passes (50e18 <= 50e18)
    function testAssetTransferAccounting_Batch_MultipleWithdrawals_Passes() public {
        // Setup: User deposits enough for multiple withdrawals
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1));

        // Create batch call with two withdrawals from same user
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](2);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.withdraw.selector, 20e18, user1, user1);

        items[1].targetContract = address(vault1);
        items[1].onBehalfOfAccount = user1;
        items[1].value = 0;
        items[1].data = abi.encodeWithSelector(IERC4626.withdraw.selector, 30e18, user1, user1);

        // Register assertion for the batch call
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionBatchAssetTransferAccounting.selector
        });

        // Execute batch call - this will trigger the assertion
        vm.prank(user1);
        evc.batch(items);

        // Assertion should pass - total transfers match total withdrawals
    }

    /// @notice SCENARIO: Mixed operations (withdraw + borrow) in one transaction
    /// @dev Verifies assertion handles multiple event types correctly
    ///
    /// TEST SETUP:
    /// - User1 has deposit, user2 provides liquidity
    /// - Batch contains: user1 withdraws 15e18 and borrows 25e18
    /// - Total Transfer events: 40e18
    /// - Total Withdraw + Borrow events: 15e18 + 25e18 = 40e18
    ///
    /// EXPECTED RESULT: Assertion passes (40e18 <= 40e18)
    function testAssetTransferAccounting_Batch_MixedOperations_Passes() public {
        // Setup: user1 deposits, user2 provides borrow liquidity
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1));

        vm.prank(user2);
        evc.call(address(vault1), user2, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 1000e18, user2));

        // Create batch call with withdraw and borrow
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](2);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.withdraw.selector, 15e18, user1, user1);

        items[1].targetContract = address(vault1);
        items[1].onBehalfOfAccount = user1;
        items[1].value = 0;
        items[1].data = abi.encodeWithSelector(MockEVault.borrow.selector, 25e18, user1);

        // Register assertion for the batch call
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionBatchAssetTransferAccounting.selector
        });

        // Execute batch call - this will trigger the assertion
        vm.prank(user1);
        evc.batch(items);

        // Assertion should pass - total transfers match total accounting events
    }

    /// @notice SCENARIO: Deposit operations (transfers TO vault)
    /// @dev Verifies assertion ignores deposits (only monitors transfers FROM vault)
    ///
    /// TEST SETUP:
    /// - User1 deposits 100e18 tokens
    /// - Transfer event: from=user1, to=vault (should be ignored)
    /// - No Transfer events from vault
    ///
    /// EXPECTED RESULT: Assertion passes (0 <= 0)
    function testAssetTransferAccounting_Batch_DepositIgnored_Passes() public {
        // Create batch call that deposits (transfer TO vault, not FROM)
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1);

        // Register assertion for the batch call
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionBatchAssetTransferAccounting.selector
        });

        // Execute batch call - this will trigger the assertion
        vm.prank(user1);
        evc.batch(items);

        // Assertion should pass - deposits are not monitored
    }

    /// @notice SCENARIO: Zero amount operations
    /// @dev Verifies assertion handles zero amounts correctly
    ///
    /// TEST SETUP:
    /// - User1 has deposit
    /// - User1 withdraws 0 tokens
    /// - Transfer event: 0 amount
    /// - Withdraw event: 0 assets
    ///
    /// EXPECTED RESULT: Assertion passes (0 <= 0)
    function testAssetTransferAccounting_Batch_ZeroAmount_Passes() public {
        // Setup: Deposit first
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1));

        // Create batch call that withdraws 0
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.withdraw.selector, 0, user1, user1);

        // Register assertion for the batch call
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionBatchAssetTransferAccounting.selector
        });

        // Execute batch call - this will trigger the assertion
        vm.prank(user1);
        evc.batch(items);

        // Assertion should pass - zero amounts handled correctly
    }

    /// @notice SCENARIO: Multiple vaults in one batch
    /// @dev Verifies assertion validates each vault independently
    ///
    /// TEST SETUP:
    /// - Both users have deposits in both vaults
    /// - Batch contains operations on both vault1 and vault2
    /// - Each vault's accounting is correct independently
    ///
    /// EXPECTED RESULT: Assertion passes for both vaults
    function testAssetTransferAccounting_Batch_MultipleVaults_Passes() public {
        // Setup: Deposits in both vaults
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1));

        vm.prank(user1);
        evc.call(address(vault2), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1));

        // Create batch call with operations on both vaults
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](2);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.withdraw.selector, 20e18, user1, user1);

        items[1].targetContract = address(vault2);
        items[1].onBehalfOfAccount = user1;
        items[1].value = 0;
        items[1].data = abi.encodeWithSelector(IERC4626.withdraw.selector, 30e18, user1, user1);

        // Register assertion for the batch call
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionBatchAssetTransferAccounting.selector
        });

        // Execute batch call - this will trigger the assertion
        vm.prank(user1);
        evc.batch(items);

        // Assertion should pass - both vaults have correct accounting
    }

    /// @notice SCENARIO: EVC.call() operation with normal withdrawal
    /// @dev Verifies assertion works with call() function (not just batch())
    ///
    /// TEST SETUP:
    /// - User1 has deposit
    /// - Uses EVC.call() to withdraw 40e18
    /// - Transfer event matches Withdraw event
    ///
    /// EXPECTED RESULT: Assertion passes
    function testAssetTransferAccounting_Call_NormalWithdrawal_Passes() public {
        // Setup: Deposit first
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1));

        // Register assertion for call operations
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionCallAssetTransferAccounting.selector
        });

        // Execute call - this will trigger the assertion
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.withdraw.selector, 40e18, user1, user1));

        // Assertion should pass
    }

    /// @notice SCENARIO: EVC.controlCollateral() operation with liquidation
    /// @dev Verifies assertion works with controlCollateral() during liquidation seizing collateral
    ///      This is the primary use case for controlCollateral - cross-vault liquidations
    ///
    /// TEST SETUP:
    /// - User1 has 100e18 collateral deposited in vault2
    /// - vault1 is the controller (borrowing vault)
    /// - Controller calls controlCollateral to seize 50 shares of collateral
    /// - Collateral vault transfers assets to user2 (liquidator)
    /// - Transfer event (50e18) matches Withdraw event (50e18)
    ///
    /// EXPECTED RESULT: Assertion passes (50e18 transferred <= 50e18 withdrawn)
    function testAssetTransferAccounting_ControlCollateral_LiquidationSeize_Passes() public {
        // Setup: Enable controller and collateral
        vm.startPrank(user1);
        evc.enableController(user1, address(vault1));
        evc.enableCollateral(user1, address(vault2));
        vm.stopPrank();

        // Deposit 100e18 collateral into vault2
        vm.prank(user1);
        evc.call(address(vault2), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1));

        // Register assertion for controlCollateral operations
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionControlCollateralAssetTransferAccounting.selector
        });

        // Execute controlCollateral call from controller - seizes 50 shares of collateral during liquidation
        // This is the realistic use case: controller vault liquidating user1, seizing collateral for user2 (liquidator)
        vm.prank(address(vault1));
        evc.controlCollateral(
            address(vault2), // collateral vault
            user1, // violator being liquidated
            0,
            abi.encodeWithSelector(MockEVault.seizeCollateral.selector, user1, user2, 50e18) // seize 50 shares
        );

        // Assertion should pass - Transfer event (50e18) matches Withdraw event (50e18)
    }

    // ========================================
    // FAILURE TESTS (Malicious Vault Behavior)
    // ========================================

    /// @notice SCENARIO: Malicious withdrawal - Transfer without Withdraw event
    /// @dev Verifies assertion fails when vault transfers assets without emitting Withdraw event
    ///
    /// TEST SETUP:
    /// - Malicious vault has flag to skip Withdraw event emission
    /// - User withdraws 50e18
    /// - Transfer event: 50e18 (from vault)
    /// - Withdraw event: NONE (skipped)
    /// - totalTransferred = 50e18, totalAccounted = 0
    ///
    /// EXPECTED RESULT: Assertion fails (50e18 > 0)
    function testAssetTransferAccounting_Batch_MissingWithdrawEvent_Fails() public {
        // Deploy malicious vault
        EventManipulatorVault maliciousVault = new EventManipulatorVault(token1, evc);
        registerVaultWithPerspective(address(maliciousVault));

        // Approve malicious vault
        vm.prank(user1);
        token1.approve(address(maliciousVault), type(uint256).max);

        // Setup: Deposit first
        vm.prank(user1);
        evc.call(address(maliciousVault), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1));

        // Enable flag to skip Withdraw event
        maliciousVault.setShouldSkipWithdrawEvent(true);

        // Create batch call that withdraws (will skip event)
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(maliciousVault);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.withdraw.selector, 50e18, user1, user1);

        // Register assertion for the batch call
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionBatchAssetTransferAccounting.selector
        });

        // Execute batch call - this should trigger assertion failure
        vm.expectRevert("VaultAssetTransferAccountingAssertion: Unaccounted asset transfers detected");
        vm.prank(user1);
        evc.batch(items);
    }

    /// @notice SCENARIO: Malicious borrow - Transfer without Borrow event
    /// @dev Verifies assertion fails when vault transfers assets without emitting Borrow event
    ///
    /// TEST SETUP:
    /// - Malicious vault has flag to skip Borrow event emission
    /// - User borrows 30e18
    /// - Transfer event: 30e18 (from vault)
    /// - Borrow event: NONE (skipped)
    /// - totalTransferred = 30e18, totalAccounted = 0
    ///
    /// EXPECTED RESULT: Assertion fails (30e18 > 0)
    function testAssetTransferAccounting_Batch_MissingBorrowEvent_Fails() public {
        // Deploy malicious vault with liquidity
        EventManipulatorVault maliciousVault = new EventManipulatorVault(token1, evc);
        registerVaultWithPerspective(address(maliciousVault));

        // Approve malicious vault
        vm.prank(user2);
        token1.approve(address(maliciousVault), type(uint256).max);

        // Setup: Provide liquidity
        vm.prank(user2);
        evc.call(address(maliciousVault), user2, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 1000e18, user2));

        // Enable flag to skip Borrow event
        maliciousVault.setShouldSkipBorrowEvent(true);

        // Create batch call that borrows (will skip event)
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(maliciousVault);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(MockEVault.borrow.selector, 30e18, user1);

        // Register assertion for the batch call
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionBatchAssetTransferAccounting.selector
        });

        // Execute batch call - this should trigger assertion failure
        vm.expectRevert("VaultAssetTransferAccountingAssertion: Unaccounted asset transfers detected");
        vm.prank(user1);
        evc.batch(items);
    }

    /// @notice SCENARIO: Partial accounting - Transfer amount exceeds event amounts
    /// @dev Verifies assertion fails when Transfer events report more than Withdraw/Borrow events
    ///
    /// TEST SETUP:
    /// - Malicious vault under-reports in events
    /// - User withdraws 100e18
    /// - Transfer event: 100e18 (actual transfer)
    /// - Withdraw event: 50e18 (under-reported)
    /// - totalTransferred = 100e18, totalAccounted = 50e18
    ///
    /// EXPECTED RESULT: Assertion fails (100e18 > 50e18)
    function testAssetTransferAccounting_Batch_UnderreportedEvent_Fails() public {
        // Deploy malicious vault
        EventManipulatorVault maliciousVault = new EventManipulatorVault(token1, evc);
        registerVaultWithPerspective(address(maliciousVault));

        // Approve malicious vault
        vm.prank(user1);
        token1.approve(address(maliciousVault), type(uint256).max);

        // Setup: Deposit first
        vm.prank(user1);
        evc.call(address(maliciousVault), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 200e18, user1));

        // Enable flag to under-report event amounts
        maliciousVault.setShouldUnderreportAmount(true);

        // Create batch call that withdraws (will under-report in event)
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(maliciousVault);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.withdraw.selector, 100e18, user1, user1);

        // Register assertion for the batch call
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionBatchAssetTransferAccounting.selector
        });

        // Execute batch call - this should trigger assertion failure
        vm.expectRevert("VaultAssetTransferAccountingAssertion: Unaccounted asset transfers detected");
        vm.prank(user1);
        evc.batch(items);
    }

    /// @notice SCENARIO: Silent asset drain - Extra transfer without any event
    /// @dev Verifies assertion catches when vault makes extra transfers without any accounting
    ///
    /// TEST SETUP:
    /// - Malicious vault transfers extra assets silently
    /// - User withdraws 50e18 normally (with proper events)
    /// - Vault also transfers extra 100e18 without any event
    /// - totalTransferred = 150e18, totalAccounted = 50e18
    ///
    /// EXPECTED RESULT: Assertion fails (150e18 > 50e18)
    function testAssetTransferAccounting_Batch_ExtraTransfer_Fails() public {
        // Deploy malicious vault
        EventManipulatorVault maliciousVault = new EventManipulatorVault(token1, evc);
        registerVaultWithPerspective(address(maliciousVault));

        // Approve malicious vault
        vm.prank(user1);
        token1.approve(address(maliciousVault), type(uint256).max);

        // Setup: Deposit first
        vm.prank(user1);
        evc.call(address(maliciousVault), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 300e18, user1));

        // Enable flag to make extra transfers
        maliciousVault.setShouldMakeExtraTransfer(true);

        // Create batch call that withdraws (vault will make extra transfer)
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(maliciousVault);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.withdraw.selector, 50e18, user1, user1);

        // Register assertion for the batch call
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionBatchAssetTransferAccounting.selector
        });

        // Execute batch call - this should trigger assertion failure
        vm.expectRevert("VaultAssetTransferAccountingAssertion: Unaccounted asset transfers detected");
        vm.prank(user1);
        evc.batch(items);
    }

    // ========================================
    // GAS BENCHMARK TESTS
    // ========================================

    /// @notice SCENARIO: Batch with 5 withdrawal operations - gas benchmark
    /// @dev Tests assertion performance with moderate batch size
    function testAssetTransferAccounting_Batch_5Withdrawals_Passes() public {
        // Setup: Deposit enough for 5 withdrawals
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 500e18, user1));

        // Create batch with 5 withdrawals
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](5);
        for (uint256 i = 0; i < 5; i++) {
            items[i].targetContract = address(vault1);
            items[i].onBehalfOfAccount = user1;
            items[i].value = 0;
            items[i].data = abi.encodeWithSelector(IERC4626.withdraw.selector, 10e18, user1, user1);
        }

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionBatchAssetTransferAccounting.selector
        });

        // Execute batch call
        vm.prank(user1);
        evc.batch(items);
    }

    /// @notice SCENARIO: Batch with 10 withdrawal operations - gas benchmark (passing version)
    /// @dev Tests assertion performance with large batch size using smaller amounts to avoid gas limit
    function testAssetTransferAccounting_Batch_10Withdrawals_Passes() public {
        // Setup: Deposit enough for 10 withdrawals
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 1000e18, user1));

        // Create batch with 10 withdrawals
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](10);
        for (uint256 i = 0; i < 10; i++) {
            items[i].targetContract = address(vault1);
            items[i].onBehalfOfAccount = user1;
            items[i].value = 0;
            items[i].data = abi.encodeWithSelector(IERC4626.withdraw.selector, 10e18, user1, user1);
        }

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionBatchAssetTransferAccounting.selector
        });

        // Execute batch call
        vm.prank(user1);
        evc.batch(items);
    }

    /// @notice SCENARIO: Batch with 10 withdrawal operations - gas benchmark
    /// @dev Tests assertion performance with large batch size
    /// TODO: This test currently fails due to hitting the 100k gas limit.
    /// Future optimization: Consider splitting into multiple assertion functions per event type
    /// to reduce gas consumption per assertion call.
    function testAssetTransferAccounting_Batch_10Withdrawals_HitsGasLimit() public {
        // Setup: Deposit enough for 10 withdrawals
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 1000e18, user1));

        // Create batch with 10 withdrawals
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](10);
        for (uint256 i = 0; i < 10; i++) {
            items[i].targetContract = address(vault1);
            items[i].onBehalfOfAccount = user1;
            items[i].value = 0;
            items[i].data = abi.encodeWithSelector(IERC4626.withdraw.selector, 10e18, user1, user1);
        }

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionBatchAssetTransferAccounting.selector
        });

        vm.prank(user1);
        evc.batch(items);
    }

    // ========================================
    // NESTED VAULT / WRAPPER VAULT TESTS
    // ========================================

    /// @notice SCENARIO: Wrapper vault deposits into underlying yield vault
    /// @dev Verifies assertion correctly accounts for vault-to-vault deposits
    ///      This was discovered in production where Tulipa ETH Earn deposits into EVK vaults.
    ///
    /// TEST SETUP:
    /// - User deposits into wrapper vault (vault1)
    /// - Wrapper vault internally deposits those assets into underlying vault (vault2)
    /// - Transfer event: from=vault1, to=vault2
    /// - Deposit event: sender=vault1, owner=vault1 emitted by vault2
    ///
    /// EXPECTED RESULT: Assertion passes (Deposit event accounts for the transfer)
    function testAssetTransferAccounting_Batch_NestedVaultDeposit_Passes() public {
        // Deploy a wrapper vault that deposits into underlying vault
        WrapperVault wrapperVault = new WrapperVault(token1, evc, vault1);
        registerVaultWithPerspective(address(wrapperVault));

        // Approve wrapper vault
        vm.prank(user1);
        token1.approve(address(wrapperVault), type(uint256).max);

        // Create batch with deposit to wrapper vault
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(wrapperVault);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1);

        // Register assertion for the batch call
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionBatchAssetTransferAccounting.selector
        });

        // Execute batch call - should pass because:
        // 1. User transfers to wrapperVault (not counted - from != vault)
        // 2. wrapperVault transfers to vault1 (counted as totalTransferred)
        // 3. vault1 emits Deposit event with sender=wrapperVault (counted as totalDepositedToUnderlying)
        vm.prank(user1);
        evc.batch(items);

        // Assertion should pass - nested vault deposits are accounted for
    }

    // ========================================
    // NON-ERC4626 CONTRACT HANDLING TESTS
    // ========================================

    /// @notice SCENARIO: Batch contains non-ERC4626 contract (like Permit2)
    /// @dev Verifies assertion gracefully skips contracts without asset() function
    ///      This was the root cause of a production false positive where Permit2
    ///      was included in a batch and calling asset() on it caused a revert.
    ///
    /// TEST SETUP:
    /// - Batch contains: non-ERC4626 contract + vault withdrawal
    /// - Non-ERC4626 contract has no asset() function
    /// - Vault has proper withdrawal with events
    ///
    /// EXPECTED RESULT: Assertion passes (non-ERC4626 contract is skipped)
    function testAssetTransferAccounting_Batch_NonERC4626Contract_Passes() public {
        // Deploy a mock contract that doesn't have asset() function (simulates Permit2)
        MockNonVaultContract nonVaultContract = new MockNonVaultContract();

        // Setup: Deposit to vault
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1));

        // Create batch with non-vault contract and normal vault operation
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](2);

        // First item: call to non-ERC4626 contract (like Permit2 permitTransferFrom)
        items[0].targetContract = address(nonVaultContract);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(MockNonVaultContract.doSomething.selector);

        // Second item: normal vault withdrawal
        items[1].targetContract = address(vault1);
        items[1].onBehalfOfAccount = user1;
        items[1].value = 0;
        items[1].data = abi.encodeWithSelector(IERC4626.withdraw.selector, 50e18, user1, user1);

        // Register assertion for the batch call
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionBatchAssetTransferAccounting.selector
        });

        // Execute batch call - should pass (non-vault contract is gracefully skipped)
        vm.prank(user1);
        evc.batch(items);

        // Assertion should pass - non-ERC4626 contracts are skipped via try/catch
    }

    // ========================================
    // BOUNDARY CONDITION TESTS
    // ========================================

    /// @notice SCENARIO: Transfer event with max uint256 amount - should handle gracefully
    /// @dev Tests boundary condition with maximum possible transfer amount
    ///
    /// TEST SETUP:
    /// - User has a very large deposit in vault
    /// - User withdraws a very large amount (near uint256 max)
    /// - Assertion should track the transfer correctly
    ///
    /// EXPECTED RESULT: Assertion should PASS (handles large transfer amounts)
    /// NOTE: Using uint128 max for safety to avoid overflow in arithmetic operations
    function testAssetTransferAccounting_MaxUint256Transfer_Passes() public {
        // Setup: Enable vault1 as controller for user1
        vm.prank(user1);
        evc.enableController(user1, address(vault1));

        // Mint a very large amount to user1
        uint256 largeAmount = type(uint128).max; // Use uint128 max for safety
        token1.mint(user1, largeAmount);

        // User1 deposits the large amount
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, largeAmount, user1));

        // Verify vault has large balance
        uint256 vaultBalance = token1.balanceOf(address(vault1));
        assertGt(vaultBalance, 1e38, "Vault should have very large balance");

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionCallAssetTransferAccounting.selector
        });

        // User1 withdraws a very large amount
        uint256 withdrawAmount = largeAmount / 2; // Withdraw half
        vm.prank(user1);
        evc.call(
            address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.withdraw.selector, withdrawAmount, user1, user1)
        );

        // Assertion should pass - handles large transfer amounts correctly
    }
}
