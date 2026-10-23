// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {BaseTest} from "../BaseTest.sol";
import {VaultExchangeRateSpikeAssertion} from "../../src/VaultExchangeRateSpikeAssertion.a.sol";
import {IEVC} from "../../../src/interfaces/IEthereumVaultConnector.sol";
import {IERC4626} from "openzeppelin-contracts/interfaces/IERC4626.sol";

// Import shared mocks
import {MockERC20} from "../mocks/MockERC20.sol";
import {MockEVault} from "../mocks/MockEVault.sol";
import {RateManipulatorVault} from "../mocks/MaliciousVaults.sol";
import {MockPerspective} from "../mocks/MockPerspective.sol";

/// @title TestVaultExchangeRateSpikeAssertion
/// @notice Test suite for VaultExchangeRateSpikeAssertion
/// @dev Tests the invariant: |rate_change| <= 5%
contract TestVaultExchangeRateSpikeAssertion is BaseTest {
    MockEVault public vault1;
    MockEVault public vault2;
    RateManipulatorVault public maliciousVault;
    MockERC20 public asset;
    MockPerspective public mockPerspective;

    /// @notice Helper to get assertion creation code with MockPerspective
    function getAssertionCreationCode() internal view returns (bytes memory) {
        address[] memory perspectives = new address[](1);
        perspectives[0] = address(mockPerspective);
        return abi.encodePacked(type(VaultExchangeRateSpikeAssertion).creationCode, abi.encode(perspectives));
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
        maliciousVault = new RateManipulatorVault(asset, evc);

        // Register vaults with the perspective
        mockPerspective.addVerifiedVault(address(vault1));
        mockPerspective.addVerifiedVault(address(vault2));
        mockPerspective.addVerifiedVault(address(maliciousVault));

        // Setup tokens (mint + approve)
        setupToken(asset, address(vault1), 10000e18);
        setupToken(asset, address(vault2), 10000e18);

        // Also approve malicious vault for user1
        vm.prank(user1);
        asset.approve(address(maliciousVault), type(uint256).max);
    }

    // ========================================
    // SUCCESS TESTS (Rate change <= 5%)
    // ========================================

    /// @notice SCENARIO: Normal deposit into empty vault
    /// @dev First deposit sets initial rate, no spike check needed
    function testExchangeRateSpike_Batch_FirstDeposit_Passes() public {
        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultExchangeRateSpikeAssertion.assertionBatchExchangeRateSpike.selector
        });

        // Create batch with first deposit
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.deposit.selector, 100e18, user1);

        // Execute batch call
        vm.prank(user1);
        evc.batch(items);

        // Assertion skips empty vault (totalSupply was 0)
    }

    /// @notice SCENARIO: Normal deposit causes minimal rate change
    /// @dev Small deposits cause negligible rate changes
    function testExchangeRateSpike_Batch_SmallDeposit_Passes() public {
        // Setup: Initial deposit to establish rate
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 1000e18, user1));

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultExchangeRateSpikeAssertion.assertionBatchExchangeRateSpike.selector
        });

        // Create batch with small deposit (1% of existing)
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.deposit.selector, 10e18, user1);

        // Execute batch call
        vm.prank(user1);
        evc.batch(items);

        // Assertion passes: rate change << 5%
    }

    /// @notice SCENARIO: Normal withdrawal causes minimal rate change
    /// @dev Small withdrawals cause negligible rate changes
    function testExchangeRateSpike_Batch_SmallWithdrawal_Passes() public {
        // Setup: Initial deposit
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 1000e18, user1));

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultExchangeRateSpikeAssertion.assertionBatchExchangeRateSpike.selector
        });

        // Create batch with small withdrawal (1% of existing)
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.withdraw.selector, 10e18, user1, user1);

        // Execute batch call
        vm.prank(user1);
        evc.batch(items);

        // Assertion passes: rate change << 5%
    }

    /// @notice SCENARIO: Rate increase at threshold (exactly 5%)
    /// @dev 5% is the maximum allowed, should pass
    function testExchangeRateSpike_Batch_ExactThreshold_Passes() public {
        // Setup: Initial deposit
        vm.prank(user1);
        evc.call(address(maliciousVault), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 1000e18, user1));

        // Set vault to inflate by exactly 5% on next deposit
        maliciousVault.setInflationBps(500); // 5% = 500 bps

        // Create batch with deposit (inflation happens DURING this deposit)
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(maliciousVault);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.deposit.selector, 1e18, user1);

        // Register assertion IMMEDIATELY before batch call
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultExchangeRateSpikeAssertion.assertionBatchExchangeRateSpike.selector
        });

        // Execute batch call
        vm.prank(user1);
        evc.batch(items);

        // Assertion passes: 5% change is at threshold
    }

    /// @notice SCENARIO: Rate increase just under threshold (4.9%)
    /// @dev Should pass comfortably
    function testExchangeRateSpike_Batch_JustUnderThreshold_Passes() public {
        // Setup: Initial deposit
        vm.prank(user1);
        evc.call(address(maliciousVault), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 1000e18, user1));

        // Set vault to inflate by 4.9% on next deposit
        maliciousVault.setInflationBps(490); // 4.9% = 490 bps

        // Create batch with deposit (inflation happens DURING this deposit)
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(maliciousVault);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.deposit.selector, 1e18, user1);

        // Register assertion IMMEDIATELY before batch call
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultExchangeRateSpikeAssertion.assertionBatchExchangeRateSpike.selector
        });

        // Execute batch call
        vm.prank(user1);
        evc.batch(items);

        // Assertion passes: 4.9% < 5%
    }

    /// @notice SCENARIO: Multiple operations on multiple vaults
    /// @dev Each vault independently validated
    function testExchangeRateSpike_Batch_MultipleVaults_Passes() public {
        // Setup: Initial deposits
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 1000e18, user1));
        vm.prank(user1);
        evc.call(address(vault2), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 500e18, user1));

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultExchangeRateSpikeAssertion.assertionBatchExchangeRateSpike.selector
        });

        // Create batch with deposits to both vaults
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](2);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.deposit.selector, 10e18, user1);

        items[1].targetContract = address(vault2);
        items[1].onBehalfOfAccount = user1;
        items[1].value = 0;
        items[1].data = abi.encodeWithSelector(IERC4626.deposit.selector, 5e18, user1);

        // Execute batch call
        vm.prank(user1);
        evc.batch(items);

        // Both vaults pass
    }

    /// @notice SCENARIO: EVC.call() operation
    /// @dev Tests assertion works with call() not just batch()
    function testExchangeRateSpike_Call_SmallDeposit_Passes() public {
        // Setup: Initial deposit
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 1000e18, user1));

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultExchangeRateSpikeAssertion.assertionCallExchangeRateSpike.selector
        });

        // Execute call with small deposit
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 10e18, user1));

        // Assertion passes
    }

    /// @notice SCENARIO: EVC.controlCollateral() operation
    /// @dev Tests assertion works with controlCollateral
    function testExchangeRateSpike_ControlCollateral_Passes() public {
        // Setup: Enable controller and collateral
        vm.startPrank(user1);
        evc.enableController(user1, address(vault1));
        evc.enableCollateral(user1, address(vault2));
        vm.stopPrank();

        // Deposit collateral
        vm.prank(user1);
        evc.call(address(vault2), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 1000e18, user1));

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultExchangeRateSpikeAssertion.assertionControlCollateralExchangeRateSpike.selector
        });

        // Execute controlCollateral - just share transfer, no rate change
        vm.prank(address(vault1));
        evc.controlCollateral(
            address(vault2), user1, 0, abi.encodeWithSelector(MockEVault.seizeCollateral.selector, user1, user2, 50e18)
        );

        // Assertion passes: no rate change
    }

    /// @notice SCENARIO: skim() operation passes with small rate change
    /// @dev skim() mints proportional shares, so rate change should be minimal (within 5%)
    ///      This test verifies skim doesn't cause rate spikes
    function testExchangeRateSpike_Batch_SkimSmallRateChange_Passes() public {
        // Setup: Initial deposit
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 1000e18, user1));

        // Create unaccounted assets (donation)
        asset.mint(address(vault1), 100e18); // 10% more assets

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultExchangeRateSpikeAssertion.assertionBatchExchangeRateSpike.selector
        });

        // Create batch with skim (claims unaccounted assets)
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(MockEVault.skim.selector, 100e18, user1);

        // Execute batch call - should pass because skim mints proportional shares
        // The rate change is minimal due to share minting mechanism
        vm.prank(user1);
        evc.batch(items);
    }

    /// @notice SCENARIO: Rate decrease >5% due to debt socialization
    /// @dev Debt socialization legitimizes large rate decreases
    function testExchangeRateSpike_Batch_DebtSocializationDecrease_Passes() public {
        // Setup: Create initial deposit to establish exchange rate
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 1000e18, user1));

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultExchangeRateSpikeAssertion.assertionBatchExchangeRateSpike.selector
        });

        // Create batch: simulate bad debt socialization causing >5% rate decrease
        // This simulates a loss of 100e18 (10% of cash), which causes rate to drop >5%
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(MockEVault.simulateBadDebtSocialization.selector, 100e18);

        // Execute batch - should pass because DebtSocialized event is emitted
        vm.prank(user1);
        evc.batch(items);

        // Assertion passes: debt socialization allows rate decrease >5%
    }

    // ========================================
    // FAILURE TESTS (Rate change > 5%)
    // ========================================

    /// @notice SCENARIO: Donation attack causing rate spike
    /// @dev Large donation increases rate beyond threshold
    function testExchangeRateSpike_Batch_DonationAttack_Fails() public {
        // Setup: Initial deposit
        vm.prank(user1);
        evc.call(address(maliciousVault), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 1000e18, user1));

        // Set malicious vault to inflate by 10% on next deposit (>5% threshold)
        maliciousVault.setInflationBps(1000); // 10% = 1000 bps

        // Create batch with deposit (inflation happens DURING this deposit)
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(maliciousVault);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.deposit.selector, 1e18, user1);

        // Register assertion IMMEDIATELY before batch call
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultExchangeRateSpikeAssertion.assertionBatchExchangeRateSpike.selector
        });

        // Execute batch call - should fail (rate increase >5%)
        vm.prank(user1);
        vm.expectRevert("VaultExchangeRateSpikeAssertion: Exchange rate spike detected");
        evc.batch(items);
    }

    /// @notice SCENARIO: Rate decrease beyond threshold
    /// @dev Loss of assets causes rate to drop >5%
    function testExchangeRateSpike_Batch_RateDecrease_Fails() public {
        // Setup: Initial deposit
        vm.prank(user1);
        evc.call(address(maliciousVault), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 1000e18, user1));

        // Set malicious vault to deflate by 10% on next deposit (>5% threshold)
        maliciousVault.setDeflationBps(1000); // 10% = 1000 bps

        // Create batch with deposit (deflation happens DURING this deposit)
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(maliciousVault);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.deposit.selector, 1e18, user1);

        // Register assertion IMMEDIATELY before batch call
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultExchangeRateSpikeAssertion.assertionBatchExchangeRateSpike.selector
        });

        // Execute batch call - should fail
        vm.prank(user1);
        vm.expectRevert("VaultExchangeRateSpikeAssertion: Exchange rate decreased >5% without debt socialization");
        evc.batch(items);
    }

    /// @notice SCENARIO: Just over threshold (5.1%)
    /// @dev Should fail even slightly over threshold
    function testExchangeRateSpike_Batch_JustOverThreshold_Fails() public {
        // Setup: Initial deposit
        vm.prank(user1);
        evc.call(address(maliciousVault), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 1000e18, user1));

        // Inflate by 5.1% (just over threshold)
        maliciousVault.setInflationBps(510); // 5.1%

        // Create batch with deposit
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(maliciousVault);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.deposit.selector, 1e18, user1);

        // Register assertion IMMEDIATELY before batch call
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultExchangeRateSpikeAssertion.assertionBatchExchangeRateSpike.selector
        });

        // Execute batch call - should fail
        vm.prank(user1);
        vm.expectRevert("VaultExchangeRateSpikeAssertion: Exchange rate spike detected");
        evc.batch(items);
    }

    /// @notice SCENARIO: Gas benchmark with 5 operations
    /// @dev Tests assertion performance
    function testExchangeRateSpike_Batch_5Operations_Passes() public {
        // Setup: Initial deposit
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 1000e18, user1));

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultExchangeRateSpikeAssertion.assertionBatchExchangeRateSpike.selector
        });

        // Create batch with 5 small deposits
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](5);
        for (uint256 i = 0; i < 5; i++) {
            items[i].targetContract = address(vault1);
            items[i].onBehalfOfAccount = user1;
            items[i].value = 0;
            items[i].data = abi.encodeWithSelector(IERC4626.deposit.selector, 1e18, user1);
        }

        vm.prank(user1);
        evc.batch(items);
    }

    /// @notice SCENARIO: Batch with 10 small deposit operations - gas benchmark
    /// @dev Tests assertion performance with large batch size
    function testExchangeRateSpike_Batch_10Operations_Passes() public {
        // Setup: Initial deposit
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 2000e18, user1));

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultExchangeRateSpikeAssertion.assertionBatchExchangeRateSpike.selector
        });

        // Create batch with 10 small deposits
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](10);
        for (uint256 i = 0; i < 10; i++) {
            items[i].targetContract = address(vault1);
            items[i].onBehalfOfAccount = user1;
            items[i].value = 0;
            items[i].data = abi.encodeWithSelector(IERC4626.deposit.selector, 1e18, user1);
        }

        vm.prank(user1);
        evc.batch(items);
    }

    // ========================================
    // BOUNDARY CONDITION TESTS
    // ========================================

    /// @notice SCENARIO: Exchange rate at uint256 boundaries - should handle gracefully
    /// @dev Tests boundary condition with very large exchange rate values
    ///
    /// TEST SETUP:
    /// - Vault has very large totalAssets and totalSupply values
    /// - User performs a deposit that slightly changes the exchange rate
    /// - Exchange rate should still be within acceptable bounds
    ///
    /// EXPECTED RESULT: Assertion should PASS (handles large exchange rate values)
    /// NOTE: Using safe large values (uint128 max) to avoid overflow while testing boundaries
    function testExchangeRateSpike_Uint256Boundaries_Passes() public {
        // Setup: Enable vault1 as controller for user1
        vm.prank(user1);
        evc.enableController(user1, address(vault1));

        // Mint a very large amount to user1 to create large exchange rate base
        uint256 largeAmount = type(uint128).max; // Use uint128 max for safety
        asset.mint(user1, largeAmount);

        // User1 makes an initial large deposit
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, largeAmount, user1));

        // Verify vault has large exchange rate base
        uint256 totalAssets = vault1.totalAssets();
        assertGt(totalAssets, 1e38, "Vault should have very large totalAssets");

        // Mint more for second deposit
        asset.mint(user1, 1000e18);

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultExchangeRateSpikeAssertion.assertionCallExchangeRateSpike.selector
        });

        // User1 makes a small deposit relative to total (should cause minimal rate change)
        vm.prank(user1);
        evc.call(address(vault1), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, 1000e18, user1));

        // Assertion should pass - rate change is minimal even with large base values
    }
}
