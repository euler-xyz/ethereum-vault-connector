// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {BaseTest} from "../BaseTest.sol";
import {VaultAssetTransferAccountingAssertion} from "../../src/VaultAssetTransferAccountingAssertion.a.sol";
import {IEVC} from "../../../src/interfaces/IEthereumVaultConnector.sol";
import {IERC4626} from "lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol";
import {MockERC20} from "../mocks/MockERC20.sol";
import {MockEVault} from "../mocks/MockEVault.sol";
import {MockPerspective} from "../mocks/MockPerspective.sol";

/// @title VaultAssetTransferAccountingAssertion Fuzz Tests
/// @notice Fuzz testing for critical VaultAssetTransferAccountingAssertion scenarios
/// @dev Property-based testing to verify asset transfer accounting invariants hold across parameter ranges
///
/// CRITICAL INVARIANT TESTED:
/// totalTransferred <= totalWithdrawn + totalBorrowed
///
/// Every asset token that leaves the vault must be accounted for by a Withdraw or Borrow event.
contract VaultAssetTransferAccountingAssertionFuzzTest is BaseTest {
    VaultAssetTransferAccountingAssertion public assertion;

    // Test vault
    MockEVault public vault;

    // Test token
    MockERC20 public token;

    // Mock perspective for vault verification
    MockPerspective public mockPerspective;

    /// @notice Helper to get assertion creation code with MockPerspective
    function getAssertionCreationCode() internal view returns (bytes memory) {
        address[] memory perspectives = new address[](1);
        perspectives[0] = address(mockPerspective);
        return abi.encodePacked(type(VaultAssetTransferAccountingAssertion).creationCode, abi.encode(perspectives));
    }

    function setUp() public override {
        super.setUp();

        // Deploy MockPerspective FIRST
        mockPerspective = new MockPerspective();
        mockPerspective.setVerifyAll(false);

        // Deploy test token
        token = new MockERC20("Test Token", "TT");

        // Deploy test vault
        vault = new MockEVault(token, evc);

        // Register vault with perspective
        mockPerspective.addVerifiedVault(address(vault));

        // Deploy assertion with perspective
        address[] memory perspectives = new address[](1);
        perspectives[0] = address(mockPerspective);
        assertion = new VaultAssetTransferAccountingAssertion(perspectives);

        // Setup test environment
        setupUserETH();

        // Setup token (mint + approve)
        setupToken(token, address(vault), 1000000e18);
    }

    /// @notice Fuzz test: Deposit operations should preserve balance invariant
    /// @dev Tests the invariant that vault balance changes match user balance changes for deposits
    ///
    /// INVARIANT: vaultBalance == sum(deposits) - sum(withdraws)
    ///
    /// TEST STRATEGY:
    /// - Fuzz deposit amount
    /// - Track vault balance before and after
    /// - Verify balance changes match deposit amount
    /// - Ensure no unaccounted transfers occur
    ///
    /// NOTE: Deposits transfer TO the vault (not FROM), so assertion should pass (0 transfers from vault).
    ///
    /// @param depositAmount Amount to deposit (bounded)
    function testFuzz_DepositBalancesMatch(
        uint256 depositAmount
    ) public {
        // Bound deposit to realistic range: 1e18 to 1000000e18
        depositAmount = bound(depositAmount, 1e18, 1000000e18);

        // Store vault balance before deposit
        uint256 vaultBalanceBefore = token.balanceOf(address(vault));
        uint256 userBalanceBefore = token.balanceOf(user1);

        // Register assertion BEFORE the transaction
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionCallAssetTransferAccounting.selector
        });

        // Execute deposit
        vm.prank(user1);
        evc.call(address(vault), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, depositAmount, user1));

        // Verify balance changes
        uint256 vaultBalanceAfter = token.balanceOf(address(vault));
        uint256 userBalanceAfter = token.balanceOf(user1);

        // Vault should have gained the deposit amount
        assertEq(vaultBalanceAfter - vaultBalanceBefore, depositAmount, "Vault balance should increase by deposit");

        // User should have lost the deposit amount
        assertEq(userBalanceBefore - userBalanceAfter, depositAmount, "User balance should decrease by deposit");

        // Assertion should pass - no transfers FROM vault (deposits are TO vault)
    }

    /// @notice Fuzz test: Withdraw operations should preserve balance invariant
    /// @dev Tests the invariant that vault balance decreases match user balance increases for withdrawals
    ///
    /// INVARIANT: userBalance + vaultBalance == constant (for a given user)
    ///
    /// TEST STRATEGY:
    /// - Setup: User deposits initial amount
    /// - Fuzz withdrawal amount (bounded by deposit)
    /// - Track balances before and after withdrawal
    /// - Verify balance changes match withdrawal amount
    /// - Ensure Transfer event is accounted for by Withdraw event
    ///
    /// @param depositAmount Initial deposit amount (bounded)
    /// @param withdrawAmount Amount to withdraw (bounded)
    function testFuzz_WithdrawBalancesMatch(
        uint256 depositAmount,
        uint256 withdrawAmount
    ) public {
        // Bound deposit to realistic range: 100e18 to 1000000e18
        depositAmount = bound(depositAmount, 100e18, 1000000e18);

        // Bound withdrawal to 1% to 100% of deposit
        withdrawAmount = bound(withdrawAmount, depositAmount / 100, depositAmount);

        // Setup: User deposits first
        vm.prank(user1);
        evc.call(address(vault), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, depositAmount, user1));

        // Store balances before withdrawal
        uint256 vaultBalanceBefore = token.balanceOf(address(vault));
        uint256 userBalanceBefore = token.balanceOf(user1);
        uint256 totalBefore = vaultBalanceBefore + userBalanceBefore;

        // Register assertion BEFORE the transaction
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionCallAssetTransferAccounting.selector
        });

        // Execute withdrawal
        vm.prank(user1);
        evc.call(
            address(vault), user1, 0, abi.encodeWithSelector(IERC4626.withdraw.selector, withdrawAmount, user1, user1)
        );

        // Verify balance changes
        uint256 vaultBalanceAfter = token.balanceOf(address(vault));
        uint256 userBalanceAfter = token.balanceOf(user1);
        uint256 totalAfter = vaultBalanceAfter + userBalanceAfter;

        // Vault should have lost the withdrawal amount
        assertEq(vaultBalanceBefore - vaultBalanceAfter, withdrawAmount, "Vault balance should decrease by withdrawal");

        // User should have gained the withdrawal amount
        assertEq(userBalanceAfter - userBalanceBefore, withdrawAmount, "User balance should increase by withdrawal");

        // Total balance should be conserved (vault + user constant)
        assertEq(totalBefore, totalAfter, "Total balance should be conserved");

        // Assertion should pass - Transfer event matches Withdraw event
    }

    /// @notice Fuzz test: Batch operations with multiple transfers should preserve total supply
    /// @dev Tests the invariant that total token supply is conserved across batch operations
    ///
    /// INVARIANT: Total token supply conservation across all operations
    ///
    /// TEST STRATEGY:
    /// - Setup: Multiple users with deposits
    /// - Fuzz: Number of operations and amounts for each
    /// - Execute batch with multiple withdrawals
    /// - Verify all transfers are accounted for by events
    /// - Ensure total supply is conserved
    ///
    /// @param numOps Number of withdrawal operations in batch (bounded to 2-5)
    /// @param seed Random seed for generating amounts
    function testFuzz_BatchMultipleTransfers(
        uint256 numOps,
        uint256 seed
    ) public {
        // Bound number of operations to 2-5 (avoid gas limit issues)
        numOps = bound(numOps, 2, 5);

        // Setup: user1 deposits large amount for multiple withdrawals
        uint256 totalDeposit = 1000e18;
        vm.prank(user1);
        evc.call(address(vault), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, totalDeposit, user1));

        // Generate withdrawal amounts using seed
        uint256[] memory amounts = new uint256[](numOps);
        uint256 totalWithdrawals = 0;

        for (uint256 i = 0; i < numOps; i++) {
            // Use seed to generate pseudo-random amounts between 10e18 and 100e18
            uint256 amount = bound(uint256(keccak256(abi.encodePacked(seed, i))), 10e18, 100e18);

            // Ensure we don't exceed available balance
            if (totalWithdrawals + amount > totalDeposit) {
                amount = totalDeposit - totalWithdrawals;
            }

            amounts[i] = amount;
            totalWithdrawals += amount;

            // Stop if we've used up the deposit
            if (totalWithdrawals >= totalDeposit) {
                // Adjust numOps to actual number we can perform
                numOps = i + 1;
                break;
            }
        }

        // Ensure we have at least some withdrawals
        vm.assume(totalWithdrawals > 0);

        // Create batch with multiple withdrawals
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](numOps);
        for (uint256 i = 0; i < numOps; i++) {
            items[i].targetContract = address(vault);
            items[i].onBehalfOfAccount = user1;
            items[i].value = 0;
            items[i].data = abi.encodeWithSelector(IERC4626.withdraw.selector, amounts[i], user1, user1);
        }

        // Store balances before batch
        uint256 vaultBalanceBefore = token.balanceOf(address(vault));
        uint256 userBalanceBefore = token.balanceOf(user1);

        // Register assertion BEFORE the transaction
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionBatchAssetTransferAccounting.selector
        });

        // Execute batch
        vm.prank(user1);
        evc.batch(items);

        // Verify total balance changes match sum of operations
        uint256 vaultBalanceAfter = token.balanceOf(address(vault));
        uint256 userBalanceAfter = token.balanceOf(user1);

        uint256 vaultDecrease = vaultBalanceBefore - vaultBalanceAfter;
        uint256 userIncrease = userBalanceAfter - userBalanceBefore;

        // All transfers should be accounted for
        assertEq(vaultDecrease, totalWithdrawals, "Vault decrease should match total withdrawals");
        assertEq(userIncrease, totalWithdrawals, "User increase should match total withdrawals");

        // Total supply should be conserved
        assertEq(
            vaultBalanceBefore + userBalanceBefore,
            vaultBalanceAfter + userBalanceAfter,
            "Total supply should be conserved"
        );

        // Assertion should pass - all Transfer events match Withdraw events
    }

    /// @notice Fuzz test: Borrow operations should have proper accounting
    /// @dev Tests the invariant that borrowed assets are properly accounted for
    ///
    /// ADDITIONAL TEST: Verifies Borrow events properly account for transfers
    ///
    /// TEST STRATEGY:
    /// - Setup: Provide liquidity from user2
    /// - Fuzz borrow amount
    /// - Execute borrow
    /// - Verify Transfer event is accounted for by Borrow event
    ///
    /// @param borrowAmount Amount to borrow (bounded)
    function testFuzz_BorrowBalancesMatch(
        uint256 borrowAmount
    ) public {
        // Bound borrow to realistic range: 1e18 to 500e18
        borrowAmount = bound(borrowAmount, 1e18, 500e18);

        // Setup: Provide liquidity from user2
        uint256 liquidity = borrowAmount * 2; // Provide 2x the borrow amount
        vm.prank(user2);
        evc.call(address(vault), user2, 0, abi.encodeWithSelector(IERC4626.deposit.selector, liquidity, user2));

        // Store balances before borrow
        uint256 vaultBalanceBefore = token.balanceOf(address(vault));
        uint256 userBalanceBefore = token.balanceOf(user1);

        // Register assertion BEFORE the transaction
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionCallAssetTransferAccounting.selector
        });

        // Execute borrow
        vm.prank(user1);
        evc.call(address(vault), user1, 0, abi.encodeWithSelector(MockEVault.borrow.selector, borrowAmount, user1));

        // Verify balance changes
        uint256 vaultBalanceAfter = token.balanceOf(address(vault));
        uint256 userBalanceAfter = token.balanceOf(user1);

        // Vault should have lost the borrow amount
        assertEq(vaultBalanceBefore - vaultBalanceAfter, borrowAmount, "Vault balance should decrease by borrow");

        // User should have gained the borrow amount
        assertEq(userBalanceAfter - userBalanceBefore, borrowAmount, "User balance should increase by borrow");

        // Assertion should pass - Transfer event matches Borrow event
    }

    /// @notice Fuzz test: Mixed operations (withdraw + borrow) should have total accounting
    /// @dev Tests the invariant with multiple operation types in one transaction
    ///
    /// TEST STRATEGY:
    /// - Setup: User1 has deposit, user2 provides liquidity
    /// - Fuzz both withdrawal and borrow amounts
    /// - Execute batch with both operations
    /// - Verify all transfers are accounted for
    ///
    /// @param withdrawAmount Amount to withdraw (bounded)
    /// @param borrowAmount Amount to borrow (bounded)
    function testFuzz_MixedOperationsAccounting(
        uint256 withdrawAmount,
        uint256 borrowAmount
    ) public {
        // Bound amounts to realistic ranges
        withdrawAmount = bound(withdrawAmount, 10e18, 100e18);
        borrowAmount = bound(borrowAmount, 10e18, 100e18);

        // Setup: user1 deposits for withdrawal
        uint256 initialDeposit = withdrawAmount * 2;
        vm.prank(user1);
        evc.call(address(vault), user1, 0, abi.encodeWithSelector(IERC4626.deposit.selector, initialDeposit, user1));

        // Setup: user2 provides liquidity for borrowing
        uint256 liquidity = borrowAmount * 2;
        vm.prank(user2);
        evc.call(address(vault), user2, 0, abi.encodeWithSelector(IERC4626.deposit.selector, liquidity, user2));

        // Store balances before operations
        uint256 vaultBalanceBefore = token.balanceOf(address(vault));
        uint256 userBalanceBefore = token.balanceOf(user1);

        // Register assertion BEFORE the transaction
        cl.assertion({
            adopter: address(evc),
            createData: getAssertionCreationCode(),
            fnSelector: VaultAssetTransferAccountingAssertion.assertionBatchAssetTransferAccounting.selector
        });

        // Create batch with withdraw and borrow
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](2);
        items[0].targetContract = address(vault);
        items[0].onBehalfOfAccount = user1;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(IERC4626.withdraw.selector, withdrawAmount, user1, user1);

        items[1].targetContract = address(vault);
        items[1].onBehalfOfAccount = user1;
        items[1].value = 0;
        items[1].data = abi.encodeWithSelector(MockEVault.borrow.selector, borrowAmount, user1);

        // Execute batch
        vm.prank(user1);
        evc.batch(items);

        // Verify total balance changes
        uint256 vaultBalanceAfter = token.balanceOf(address(vault));
        uint256 userBalanceAfter = token.balanceOf(user1);

        uint256 totalTransferred = withdrawAmount + borrowAmount;
        uint256 vaultDecrease = vaultBalanceBefore - vaultBalanceAfter;
        uint256 userIncrease = userBalanceAfter - userBalanceBefore;

        // Total transfers should match sum of operations
        assertEq(vaultDecrease, totalTransferred, "Vault decrease should match total transfers");
        assertEq(userIncrease, totalTransferred, "User increase should match total transfers");

        // Assertion should pass - all Transfer events match Withdraw + Borrow events
    }
}
