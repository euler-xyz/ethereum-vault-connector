// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {BaseTest} from "../BaseTest.sol";
import {VaultSharePriceAssertion} from "../../src/VaultSharePriceAssertion.a.sol";
import {IEVC} from "../../../src/interfaces/IEthereumVaultConnector.sol";
import {IERC4626} from "lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {ERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {ERC4626} from "lib/openzeppelin-contracts/contracts/token/ERC20/extensions/ERC4626.sol";
import {MockERC20} from "../mocks/MockERC20.sol";
import {MockPerspective} from "../mocks/MockPerspective.sol";

/// @title TestVaultSharePriceAssertion
/// @notice Comprehensive test suite for the VaultSharePriceAssertion assertion
contract TestVaultSharePriceAssertion is BaseTest {
    VaultSharePriceAssertion public assertion;

    // Test vaults
    MockERC4626Vault public vault1;
    MockERC4626Vault public vault2;
    MockERC4626Vault public vault3;

    // Test tokens
    MockERC20 public token1;
    MockERC20 public token2;
    MockERC20 public token3;

    // Controller vault for controlCollateral tests
    MockControllerVault public controllerVault;

    // Mock perspective for vault verification
    MockPerspective public mockPerspective;

    /// @notice Helper to get assertion creation code with MockPerspective
    /// @dev Passes the mockPerspective address to the assertion constructor
    function getAssertionCreationCode() internal view returns (bytes memory) {
        address[] memory perspectives = new address[](1);
        perspectives[0] = address(mockPerspective);
        return abi.encodePacked(type(VaultSharePriceAssertion).creationCode, abi.encode(perspectives));
    }

    function setUp() public override {
        super.setUp();

        // Deploy MockPerspective FIRST (before vaults)
        mockPerspective = new MockPerspective();
        mockPerspective.setVerifyAll(false); // Only verify explicitly added vaults

        // Deploy test tokens
        token1 = new MockERC20("Test Token 1", "TT1");
        token2 = new MockERC20("Test Token 2", "TT2");
        token3 = new MockERC20("Test Token 3", "TT3");

        // Deploy test vaults
        vault1 = new MockERC4626Vault(token1);
        vault2 = new MockERC4626Vault(token2);
        vault3 = new MockERC4626Vault(token3);

        // Register vaults with the perspective
        mockPerspective.addVerifiedVault(address(vault1));
        mockPerspective.addVerifiedVault(address(vault2));
        mockPerspective.addVerifiedVault(address(vault3));

        // Deploy assertion with perspective
        address[] memory perspectives = new address[](1);
        perspectives[0] = address(mockPerspective);
        assertion = new VaultSharePriceAssertion(perspectives);

        // Deploy controller vault
        controllerVault = new MockControllerVault();

        // Setup test environment
        setupUserETH();

        // Mint tokens to test addresses (no vault approval needed for MockERC4626Vault)
        mintTokensToUsers(token1, 1000000e18);
        mintTokensToUsers(token2, 1000000e18);
        mintTokensToUsers(token3, 1000000e18);
    }

    /// @notice Tests normal vault operation - share price increases
    /// @dev Expected: pass share price increased
    function testVaultSharePriceAssertion_SharePriceIncrease_Passes() public {
        // Setup vault with initial state
        token1.mint(address(vault1), 1000e18);
        vault1.setTotalAssets(1000e18);
        // Mint shares to set totalSupply (ERC4626 manages this internally)
        vault1.mint(1000e18, user1); // Share price = 1.0

        // Create batch call that increases share price
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(MockERC4626Vault.increaseSharePrice.selector, 100e18);

        // Register assertion for the batch call (this will trigger on the next call)
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultSharePriceAssertion.assertionBatchSharePriceInvariant.selector
        });

        // Execute batch call - this will trigger the assertion
        vm.prank(user1);
        evc.batch(items);

        // Assertion should pass - share price increased
    }

    /// @notice Tests neutral vault operation - share price unchanged
    /// @dev Expected: pass share price unchanged
    function testVaultSharePriceAssertion_SharePriceUnchanged_Passes() public {
        // Setup vault with initial state
        token1.mint(address(vault1), 1000e18);
        vault1.setTotalAssets(1000e18);
        // Mint shares to set totalSupply (ERC4626 manages this internally)
        vault1.mint(1000e18, user1); // Share price = 1.0

        // Create batch call that doesn't change share price
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(MockERC4626Vault.noOp.selector);

        // Register assertion for the batch call
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultSharePriceAssertion.assertionBatchSharePriceInvariant.selector
        });

        // Execute batch call - this will trigger the assertion
        vm.prank(user1);
        evc.batch(items);

        // Assertion should pass - share price unchanged
    }

    /// @notice Tests suspicious vault operation - share price decreases without bad debt socialization
    /// @dev Expected: fail share price decreased without bad debt socialization
    function testVaultSharePriceAssertion_SharePriceDecreaseWithoutBadDebt_Fails() public {
        // Setup vault with initial state
        token1.mint(address(vault1), 1000e18);
        vault1.setTotalAssets(1000e18);
        // Mint shares to set totalSupply (ERC4626 manages this internally)
        vault1.mint(1000e18, user1); // Share price = 1.0

        // Create batch call that decreases share price without bad debt socialization
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(MockERC4626Vault.decreaseSharePrice.selector, 100e18);

        // Register assertion for the batch call
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultSharePriceAssertion.assertionBatchSharePriceInvariant.selector
        });

        // Execute batch call - should fail
        vm.prank(user1);
        vm.expectRevert("VaultSharePriceAssertion: Share price decreased without bad debt socialization");
        evc.batch(items);
    }

    /// @notice Tests legitimate vault operation - share price decreases with bad debt socialization
    /// @dev Expected: pass share price decreased with legitimate bad debt socialization
    function testVaultSharePriceAssertion_SharePriceDecreaseWithBadDebt_Passes() public {
        // Setup vault with initial state
        token1.mint(address(vault1), 1000e18);
        vault1.setTotalAssets(1000e18);
        // Mint shares to set totalSupply (ERC4626 manages this internally)
        vault1.mint(1000e18, user1); // Share price = 1.0

        // Create batch call that decreases share price with bad debt socialization
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(MockERC4626Vault.decreaseSharePriceWithBadDebt.selector, 100e18);

        // Register assertion for the batch call
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultSharePriceAssertion.assertionBatchSharePriceInvariant.selector
        });

        // Execute batch call - this will trigger the assertion
        vm.prank(user1);
        evc.batch(items);

        // Assertion should pass - share price decreased but with bad debt socialization
    }

    /// @notice Tests complex batch operation - multiple vaults in single batch
    /// @dev Expected: pass both vaults have valid share price changes
    function testVaultSharePriceAssertion_MultipleVaultsInBatch_Passes() public {
        // Setup vaults with initial state
        token1.mint(address(vault1), 1000e18);
        token2.mint(address(vault2), 1000e18);
        token3.mint(address(vault3), 1000e18);

        vault1.setTotalAssets(1000e18);
        vault1.mint(1000e18, user1);
        vault2.setTotalAssets(1000e18);
        vault2.mint(1000e18, user1);
        vault3.setTotalAssets(1000e18);
        vault3.mint(1000e18, user1);

        // Create batch call with multiple vaults
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](3);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(MockERC4626Vault.increaseSharePrice.selector, 50e18);

        items[1].targetContract = address(vault2);
        items[1].onBehalfOfAccount = user1;
        items[1].value = 0;
        items[1].data = abi.encodeWithSelector(MockERC4626Vault.noOp.selector);

        items[2].targetContract = address(vault3);
        items[2].onBehalfOfAccount = user1;
        items[2].value = 0;
        items[2].data = abi.encodeWithSelector(MockERC4626Vault.increaseSharePrice.selector, 25e18);

        // Register assertion for next transaction
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultSharePriceAssertion.assertionBatchSharePriceInvariant.selector
        });

        // Execute batch call
        vm.prank(user1);
        evc.batch(items);

        // Assertion should pass - all vaults have valid share price changes
    }

    /// @notice Tests single call to vault - expected: success
    function testVaultSharePriceAssertion_SingleCall_Passes() public {
        // Setup vault with initial state
        token1.mint(address(vault1), 1000e18);
        vault1.setTotalAssets(1000e18);
        vault1.mint(1000e18, user1);

        // Register assertion for next transaction
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultSharePriceAssertion.assertionCallSharePriceInvariant.selector
        });

        // Execute single call
        vm.prank(user1);
        evc.call(
            address(vault1), user1, 0, abi.encodeWithSelector(MockERC4626Vault.increaseSharePrice.selector, 100e18)
        );

        // Assertion should pass
    }

    /// @notice Tests single call to vault - expected: failure
    function testVaultSharePriceAssertion_SingleCall_Fails() public {
        // Setup vault with initial state
        token1.mint(address(vault1), 1000e18);
        vault1.setTotalAssets(1000e18);
        vault1.mint(1000e18, user1);

        // Register assertion for next transaction
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultSharePriceAssertion.assertionCallSharePriceInvariant.selector
        });

        // Execute single call that decreases share price without bad debt socialization
        vm.prank(user1);
        vm.expectRevert("VaultSharePriceAssertion: Share price decreased without bad debt socialization");
        evc.call(
            address(vault1), user1, 0, abi.encodeWithSelector(MockERC4626Vault.decreaseSharePrice.selector, 100e18)
        );
    }

    /// @notice Tests control collateral call - expected: success
    function testVaultSharePriceAssertion_ControlCollateral_Passes() public {
        // Setup vault with initial state
        token1.mint(address(vault1), 1000e18);
        vault1.setTotalAssets(1000e18);
        vault1.mint(1000e18, user1);

        // Setup controller/collateral relationships
        // 1. Enable controller for user1
        vm.prank(user1);
        evc.enableController(user1, address(controllerVault));

        // 2. Enable collateral for user1
        vm.prank(user1);
        evc.enableCollateral(user1, address(vault1));

        // Register assertion for next transaction
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultSharePriceAssertion.assertionControlCollateralSharePriceInvariant.selector
        });

        // Execute control collateral call from controller
        vm.prank(address(controllerVault));
        evc.controlCollateral(
            address(vault1), user1, 0, abi.encodeWithSelector(MockERC4626Vault.increaseSharePrice.selector, 100e18)
        );

        // Assertion should pass
    }

    /// @notice Tests control collateral call - expected: failure
    function testVaultSharePriceAssertion_ControlCollateral_Fails() public {
        // Setup vault with initial state
        token1.mint(address(vault1), 1000e18);
        vault1.setTotalAssets(1000e18);
        vault1.mint(1000e18, user1);

        // Setup controller/collateral relationships
        // 1. Enable controller for user1
        vm.prank(user1);
        evc.enableController(user1, address(controllerVault));

        // 2. Enable collateral for user1
        vm.prank(user1);
        evc.enableCollateral(user1, address(vault1));

        // Register assertion for next transaction
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultSharePriceAssertion.assertionControlCollateralSharePriceInvariant.selector
        });

        // Execute control collateral call that decreases share price without bad debt socialization
        vm.prank(address(controllerVault));
        vm.expectRevert("VaultSharePriceAssertion: Share price decreased without bad debt socialization");
        evc.controlCollateral(
            address(vault1), user1, 0, abi.encodeWithSelector(MockERC4626Vault.decreaseSharePrice.selector, 100e18)
        );
    }

    /// @notice Tests edge case - non-erc4626 contract in batch
    /// @dev Expected: pass non-ERC4626 contracts are skipped gracefully
    function testVaultSharePriceAssertion_NonERC4626Contract_Passes() public {
        // Create batch call with non-ERC4626 contract
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(token1); // ERC20 token, not ERC4626
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        // Use a function that doesn't require token ownership - just call balanceOf
        items[0].data = abi.encodeWithSelector(ERC20.balanceOf.selector, user1);

        // Register assertion for next transaction
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultSharePriceAssertion.assertionBatchSharePriceInvariant.selector
        });

        // Execute batch call - this should work since balanceOf doesn't require ownership
        vm.prank(user1);
        evc.batch(items);

        // Assertion should pass - non-ERC4626 contracts are skipped
    }

    /// @notice Tests edge case - zero address in batch
    /// @dev Expected: pass zero addresses are skipped gracefully
    function testVaultSharePriceAssertion_ZeroAddress_Passes() public {
        // Create batch call with zero address
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(0);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = "";

        // Register assertion for next transaction
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultSharePriceAssertion.assertionBatchSharePriceInvariant.selector
        });

        // Execute batch call
        vm.prank(user1);
        evc.batch(items);

        // Assertion should pass - zero addresses are skipped
    }

    /// @notice Tests edge case - vault with zero total supply
    /// @dev Expected: pass zero total supply is handled gracefully
    function testVaultSharePriceAssertion_ZeroTotalSupply_Passes() public {
        // Setup vault with zero total supply
        vault1.setTotalAssets(0);
        // No shares minted, so totalSupply = 0 (Share price = 0)

        // Create batch call
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(vault1);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(MockERC4626Vault.noOp.selector);

        // Register assertion for next transaction
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultSharePriceAssertion.assertionBatchSharePriceInvariant.selector
        });

        // Execute batch call
        vm.prank(user1);
        evc.batch(items);

        // Assertion should pass - zero total supply is handled gracefully
    }

    /// @notice Tests zero assets but non-zero shares - should handle edge case
    /// @dev Expected: pass handles zero asset edge case
    /// NOTE: This represents an extreme loss scenario - assertion should not revert on math errors
    function testVaultSharePrice_ZeroAssetsNonZeroShares_Handles() public {
        // Deploy a fresh mock vault (not used as controller)
        MockERC4626Vault testVault = new MockERC4626Vault(token1);

        // Set initial totalAssets to simulate normal vault state
        testVault.setTotalAssets(1000e18);

        // Mint shares directly to user (deposit not implemented in mock)
        testVault.mint(1000e18, user1);

        // Verify shares were created
        uint256 shares = testVault.balanceOf(user1);
        assertGt(shares, 0, "User should have shares");

        // Record initial assets
        uint256 initialAssets = testVault.totalAssets();
        assertGt(initialAssets, 0, "Initial assets should be non-zero");

        // Simulate catastrophic loss - set assets to 0 while shares remain
        testVault.setTotalAssets(0);

        // Verify edge case: zero assets, non-zero shares (share price = 0)
        assertEq(testVault.totalAssets(), 0, "Assets should be zero");
        assertGt(testVault.totalSupply(), 0, "Supply should be non-zero");

        // Register assertion for batch operation
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultSharePriceAssertion.assertionBatchSharePriceInvariant.selector
        });

        // Execute a batch with no-op to trigger assertion
        // The assertion should handle the zero assets case without reverting
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(testVault);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(MockERC4626Vault.noOp.selector);

        vm.prank(user1);
        evc.batch(items);

        // Assertion should pass - handles zero assets / non-zero shares edge case
    }

    /// @notice Tests that VIRTUAL_DEPOSIT formula prevents false positives on small vaults
    /// @dev This test replicates the exact scenario from Linea tx 0x4ec425f3... where a small vault
    /// (~279 USDC) had a deposit that appeared to decrease share price without VIRTUAL_DEPOSIT,
    /// but actually increased when using Euler's correct formula with VIRTUAL_DEPOSIT_AMOUNT (1e6).
    ///
    /// The math:
    /// - Pre-tx:  totalAssets=279193303, totalSupply=261048732, ratio=1.069506451
    /// - Deposit: +25468 assets, +23816 shares (ratio=1.0694 < existing ratio)
    /// - Post-tx: totalAssets=279218771, totalSupply=261072548
    ///
    /// WITHOUT VIRTUAL_DEPOSIT (1e6):
    ///   Pre:  279193303 / 261048732 = 1.069506451
    ///   Post: 279218771 / 261072548 = 1.069506438
    ///   Result: DECREASE (false positive!)
    ///
    /// WITH VIRTUAL_DEPOSIT (1e6):
    ///   Pre:  (279193303 + 1e6) / (261048732 + 1e6) = 1.069241209
    ///   Post: (279218771 + 1e6) / (261072548 + 1e6) = 1.069241220
    ///   Result: INCREASE (correct!)
    function testVaultSharePriceAssertion_SmallVaultDeposit_VirtualDepositPreventsFalsePositive() public {
        // Deploy a fresh mock vault for this specific test
        MockERC4626Vault smallVault = new MockERC4626Vault(token1);

        // Set up the exact pre-transaction state from Linea tx
        // These are USDC values (6 decimals), scaled values from the real transaction
        uint256 preAssets = 279193303;
        uint256 preSupply = 261048732;

        // Mint tokens to cover assets
        token1.mint(address(smallVault), preAssets);
        smallVault.setTotalAssets(preAssets);
        smallVault.mint(preSupply, user1);

        // Verify initial state
        assertEq(smallVault.totalAssets(), preAssets, "Pre assets mismatch");
        assertEq(smallVault.totalSupply(), preSupply, "Pre supply mismatch");

        // The deposit that caused the false positive:
        // +25468 assets, +23816 shares (ratio 1.0694, below existing 1.0695)
        uint256 depositAssets = 25468;
        uint256 depositShares = 23816;

        // Register assertion
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultSharePriceAssertion.assertionBatchSharePriceInvariant.selector
        });

        // Create batch call that simulates the deposit
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(smallVault);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data =
            abi.encodeWithSelector(MockERC4626Vault.simulateDeposit.selector, depositAssets, depositShares, user1);

        // Execute batch call - should PASS with VIRTUAL_DEPOSIT formula
        // Without VIRTUAL_DEPOSIT, this would fail with "Share price decreased without bad debt socialization"
        vm.prank(user1);
        evc.batch(items);

        // Verify final state matches expected
        assertEq(smallVault.totalAssets(), preAssets + depositAssets, "Post assets mismatch");
        assertEq(smallVault.totalSupply(), preSupply + depositShares, "Post supply mismatch");

        // Demonstrate the math difference
        uint256 VIRTUAL_DEPOSIT = 1e6;

        // Without VIRTUAL_DEPOSIT (incorrect formula that caused false positive)
        uint256 preRateNoVD = (preAssets * 1e18) / preSupply;
        uint256 postRateNoVD = ((preAssets + depositAssets) * 1e18) / (preSupply + depositShares);

        // With VIRTUAL_DEPOSIT (correct Euler formula)
        uint256 preRateWithVD = ((preAssets + VIRTUAL_DEPOSIT) * 1e18) / (preSupply + VIRTUAL_DEPOSIT);
        uint256 postRateWithVD =
            ((preAssets + depositAssets + VIRTUAL_DEPOSIT) * 1e18) / (preSupply + depositShares + VIRTUAL_DEPOSIT);

        // Assert the key insight: without VD it decreases, with VD it increases
        assertLt(postRateNoVD, preRateNoVD, "Without VD: rate should decrease (false positive scenario)");
        assertGt(postRateWithVD, preRateWithVD, "With VD: rate should increase (correct behavior)");
    }
}

/// @title MockERC4626Vault
/// @notice Mock ERC4626 vault for testing
contract MockERC4626Vault is ERC4626 {
    uint256 private _totalAssets;

    // Events for bad debt socialization simulation
    event Repay(address indexed account, uint256 assets);

    constructor(
        ERC20 assetToken
    ) ERC4626(assetToken) ERC20("Mock Vault", "MV") {}

    function setTotalAssets(
        uint256 assets
    ) external {
        _totalAssets = assets;
    }

    function totalAssets() public view override returns (uint256) {
        return _totalAssets;
    }

    function increaseSharePrice(
        uint256 amount
    ) external {
        _totalAssets += amount;
        // Keep total supply the same to increase share price
    }

    function decreaseSharePrice(
        uint256 amount
    ) external {
        require(_totalAssets >= amount, "Insufficient assets");
        _totalAssets -= amount;
        // Keep total supply the same to decrease share price
        // No events emitted - this simulates malicious share price decrease
    }

    function decreaseSharePriceWithBadDebt(
        uint256 amount
    ) external {
        require(_totalAssets >= amount, "Insufficient assets");
        _totalAssets -= amount;
        // Keep total supply the same to decrease share price

        // Emit events to simulate bad debt socialization as per Euler whitepaper:
        // - Repay event from liquidator (not address(0))
        // - Withdraw event from address(0)
        address liquidator = address(0x1234567890123456789012345678901234567890); // Mock liquidator
        emit Repay(liquidator, amount);
        emit Withdraw(address(0), address(0), address(0), amount, 0);
    }

    function noOp() external {
        // Do nothing
    }

    /// @notice Simulates a deposit with specific assets and shares
    /// @dev Used to test the VIRTUAL_DEPOSIT formula by creating deposits at specific ratios
    /// that would trigger false positives without the correct formula
    function simulateDeposit(
        uint256 assets,
        uint256 shares,
        address receiver
    ) external {
        _totalAssets += assets;
        _mint(receiver, shares);
    }

    // Required IVault interface functions
    function checkVaultStatus() external pure returns (bytes4) {
        return this.checkVaultStatus.selector;
    }

    // Required ERC4626 functions (simplified for testing)
    function deposit(
        uint256,
        address
    ) public pure override returns (uint256) {
        revert("Not implemented for testing");
    }

    function mint(
        uint256 shares,
        address receiver
    ) public override returns (uint256) {
        _mint(receiver, shares);
        return shares;
    }

    function withdraw(
        uint256,
        address,
        address
    ) public pure override returns (uint256) {
        revert("Not implemented for testing");
    }

    function redeem(
        uint256,
        address,
        address
    ) public pure override returns (uint256) {
        revert("Not implemented for testing");
    }

    function maxDeposit(
        address
    ) public pure override returns (uint256) {
        return type(uint256).max;
    }

    function maxMint(
        address
    ) public pure override returns (uint256) {
        return type(uint256).max;
    }

    function maxWithdraw(
        address
    ) public pure override returns (uint256) {
        return type(uint256).max;
    }

    function maxRedeem(
        address
    ) public pure override returns (uint256) {
        return type(uint256).max;
    }

    function previewDeposit(
        uint256
    ) public pure override returns (uint256) {
        return 0;
    }

    function previewMint(
        uint256
    ) public pure override returns (uint256) {
        return 0;
    }

    function previewWithdraw(
        uint256
    ) public pure override returns (uint256) {
        return 0;
    }

    function previewRedeem(
        uint256
    ) public pure override returns (uint256) {
        return 0;
    }

    function convertToShares(
        uint256
    ) public pure override returns (uint256) {
        return 0;
    }

    function convertToAssets(
        uint256
    ) public pure override returns (uint256) {
        return 0;
    }
}

/// @title MockControllerVault
/// @notice Mock controller vault for testing controlCollateral functionality
contract MockControllerVault {
    // Simple controller vault that can be used for controlCollateral tests
    // Implements the required checkAccountStatus function that EVC expects from controllers

    function checkAccountStatus(
        address,
        address[] memory
    ) external pure returns (bytes4) {
        return this.checkAccountStatus.selector;
    }
}
