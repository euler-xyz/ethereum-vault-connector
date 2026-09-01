// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {BaseTest} from "../BaseTest.sol";
import {VaultSharePriceAssertion} from "../../src/VaultSharePriceAssertion.a.sol";
import {IEVC} from "../../../src/interfaces/IEthereumVaultConnector.sol";
import {MockERC20} from "../mocks/MockERC20.sol";
import {MockSharePriceVault} from "../mocks/MockSharePriceVault.sol";
import {MockPerspective} from "../mocks/MockPerspective.sol";

/// @title VaultSharePriceAssertion Fuzz Tests
/// @notice Fuzz testing for critical VaultSharePriceAssertion scenarios
/// @dev Property-based testing to verify share price invariants hold across parameter ranges
///
/// CRITICAL INVARIANTS TESTED:
/// 1. Share price changes > 5% (decrease) without bad debt socialization must revert
/// 2. Share price decreases with bad debt socialization events must pass
/// 3. Share price increases (from skim operations) must always pass
contract VaultSharePriceAssertionFuzzTest is BaseTest {
    VaultSharePriceAssertion public assertion;

    // Test vault
    MockSharePriceVault public vault;

    // Test token
    MockERC20 public token;

    // Mock perspective for vault verification
    MockPerspective public mockPerspective;

    /// @notice Helper to get assertion creation code with MockPerspective
    function getAssertionCreationCode() internal view returns (bytes memory) {
        address[] memory perspectives = new address[](1);
        perspectives[0] = address(mockPerspective);
        return abi.encodePacked(type(VaultSharePriceAssertion).creationCode, abi.encode(perspectives));
    }

    function setUp() public override {
        super.setUp();

        // Deploy MockPerspective FIRST
        mockPerspective = new MockPerspective();
        mockPerspective.setVerifyAll(false);

        // Deploy test token
        token = new MockERC20("Test Token", "TT");

        // Deploy test vault
        vault = new MockSharePriceVault(token);

        // Register vault with perspective
        mockPerspective.addVerifiedVault(address(vault));

        // Deploy assertion with perspective
        address[] memory perspectives = new address[](1);
        perspectives[0] = address(mockPerspective);
        assertion = new VaultSharePriceAssertion(perspectives);

        // Setup test environment
        setupUserETH();

        // Mint tokens to test addresses
        mintTokensToUsers(token, 1000000e18);
    }

    /// @notice Fuzz test: Exchange rate spikes exceeding threshold should revert
    /// @dev Tests the invariant that share price decreases > 5% without bad debt socialization must fail
    ///
    /// INVARIANT: Share price decrease > 5% must have bad debt socialization OR revert
    ///
    /// TEST STRATEGY:
    /// - Fuzz initial share price (realistic vault values)
    /// - Fuzz rate decrease percentage (focus on values > 5% threshold)
    /// - Calculate final share price from rate change
    /// - Ensure rate decreases > 5% without bad debt events cause revert
    ///
    /// NOTE: We only test DECREASES here because the assertion only reverts on decreases.
    /// Increases are tested in testFuzz_Skim_WithinLimits_Passes.
    ///
    /// @param initialRate Initial share price (bounded to realistic range)
    /// @param rateDecreasePercent Rate decrease in basis points (10000 = 100%)
    function testFuzz_Spike_ExceedsThreshold_Reverts(
        uint256 initialRate,
        uint256 rateDecreasePercent
    ) public {
        // Bound initial rate to realistic range: 0.1e18 to 10e18 (0.1 to 10 assets per share)
        initialRate = bound(initialRate, 0.1e18, 10e18);

        // Bound rate decrease to 6% to 50% (testing threshold violations)
        // Focus on range that should fail: > 5%
        rateDecreasePercent = bound(rateDecreasePercent, 501, 5000); // 5.01% to 50%

        // Setup vault with initial state
        // Share price = totalAssets / totalSupply
        // We'll use 1000e18 shares and calculate assets accordingly
        uint256 totalSupply = 1000e18;
        uint256 initialAssets = (initialRate * totalSupply) / 1e18;

        // Ensure we have enough tokens to cover initial assets
        token.mint(address(vault), initialAssets);
        vault.setTotalAssets(initialAssets);
        vault.mint(totalSupply, user1);

        // Verify initial share price
        uint256 actualInitialPrice = (vault.totalAssets() * 1e18) / vault.totalSupply();
        assertApproxEqAbs(actualInitialPrice, initialRate, 1e10, "Initial price mismatch");

        // Calculate the asset decrease needed
        uint256 assetDecrease = (initialAssets * rateDecreasePercent) / 10000;

        // Ensure we don't underflow
        vm.assume(assetDecrease < initialAssets);

        // Register assertion BEFORE the transaction
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultSharePriceAssertion.assertionBatchSharePriceInvariant.selector
        });

        // Create batch call that decreases share price beyond threshold WITHOUT bad debt
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(MockSharePriceVault.decreaseSharePrice.selector, assetDecrease);

        // Execute batch call - should REVERT (rate decrease exceeds 5% without bad debt)
        vm.prank(user1);
        vm.expectRevert("VaultSharePriceAssertion: Share price decreased without bad debt socialization");
        evc.batch(items);
    }

    /// @notice Fuzz test: Share price decreases with bad debt socialization should always pass
    /// @dev Tests the invariant that large decreases are allowed when bad debt events occur
    ///
    /// INVARIANT: Share price can decrease by any amount IF bad debt socialization occurred
    ///
    /// TEST STRATEGY:
    /// - Fuzz initial share price
    /// - Fuzz loss amount (representing bad debt)
    /// - Emit proper bad debt events (Repay + Withdraw from address(0))
    /// - Verify decrease is allowed with events
    ///
    /// @param initialAssets Initial vault assets (bounded)
    /// @param lossAmount Amount of bad debt loss (bounded)
    function testFuzz_DebtSocialization_AllowsDecrease(
        uint256 initialAssets,
        uint256 lossAmount
    ) public {
        // Bound initial assets to realistic range: 1000e18 to 1000000e18
        initialAssets = bound(initialAssets, 1000e18, 1000000e18);

        // Bound loss to 6% to 50% of initial assets (must exceed 5% threshold to test the invariant)
        uint256 minLoss = (initialAssets * 6) / 100; // 6%
        uint256 maxLoss = initialAssets / 2; // 50%
        lossAmount = bound(lossAmount, minLoss, maxLoss);

        // Ensure loss doesn't exceed total assets
        vm.assume(lossAmount < initialAssets);

        // Setup vault with initial state
        uint256 totalSupply = 1000e18;
        token.mint(address(vault), initialAssets);
        vault.setTotalAssets(initialAssets);
        vault.mint(totalSupply, user1);

        // Calculate rate decrease percentage for validation
        uint256 initialRate = (initialAssets * 1e18) / totalSupply;
        uint256 finalAssets = initialAssets - lossAmount;
        uint256 finalRate = (finalAssets * 1e18) / totalSupply;
        uint256 rateDecrease = ((initialRate - finalRate) * 10000) / initialRate; // In basis points

        // Verify we're testing significant decreases (> 5%)
        assertGt(rateDecrease, 500, "Should test decreases > 5%");

        // Register assertion BEFORE the transaction
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultSharePriceAssertion.assertionBatchSharePriceInvariant.selector
        });

        // Create batch call that decreases share price WITH bad debt socialization
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(MockSharePriceVault.decreaseSharePriceWithBadDebt.selector, lossAmount);

        // Execute batch call - should PASS (bad debt socialization allows decrease)
        vm.prank(user1);
        evc.batch(items);

        // Verify share price decreased
        uint256 actualFinalRate = (vault.totalAssets() * 1e18) / vault.totalSupply();
        assertLt(actualFinalRate, initialRate, "Share price should have decreased");
    }

    /// @notice Fuzz test: Share price increases (skim operations) should always pass
    /// @dev Tests the invariant that share price increases are always legitimate
    ///
    /// INVARIANT: Share price increases should never revert (no maximum threshold)
    ///
    /// TEST STRATEGY:
    /// - Fuzz initial share price
    /// - Fuzz rate increase amount
    /// - Execute skim operation (adds excess assets)
    /// - Verify operation passes regardless of increase magnitude
    ///
    /// NOTE: In real vaults, skim operations collect excess assets that increase share price.
    /// These are always legitimate and should never trigger the assertion.
    ///
    /// @param initialAssets Initial vault assets (bounded)
    /// @param excessAssets Excess assets from skim (bounded)
    function testFuzz_Skim_WithinLimits_Passes(
        uint256 initialAssets,
        uint256 excessAssets
    ) public {
        // Bound initial assets to realistic range: 100e18 to 1000000e18
        initialAssets = bound(initialAssets, 100e18, 1000000e18);

        // Bound excess assets to 1% to 1000% of initial assets
        // (testing both small gains and massive yield events)
        uint256 minExcess = initialAssets / 100; // 1%
        uint256 maxExcess = initialAssets * 10; // 1000%
        excessAssets = bound(excessAssets, minExcess, maxExcess);

        // Setup vault with initial state
        uint256 totalSupply = 1000e18;
        token.mint(address(vault), initialAssets);
        vault.setTotalAssets(initialAssets);
        vault.mint(totalSupply, user1);

        // Store initial rate for verification
        uint256 initialRate = (initialAssets * 1e18) / totalSupply;

        // Register assertion BEFORE the transaction
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultSharePriceAssertion.assertionBatchSharePriceInvariant.selector
        });

        // Create batch call that increases share price (simulating skim operation)
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(MockSharePriceVault.increaseSharePrice.selector, excessAssets);

        // Execute batch call - should PASS (increases always allowed)
        vm.prank(user1);
        evc.batch(items);

        // Verify share price increased
        uint256 actualFinalRate = (vault.totalAssets() * 1e18) / vault.totalSupply();
        assertGt(actualFinalRate, initialRate, "Share price should have increased");
    }
}
