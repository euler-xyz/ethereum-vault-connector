// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Assertion} from "credible-std/Assertion.sol";
import {PhEvm} from "credible-std/PhEvm.sol";
import {IEVC} from "../../src/interfaces/IEthereumVaultConnector.sol";
import {IERC4626} from "lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol";
import {IPerspective} from "./interfaces/IPerspective.sol";

/// @title VaultSharePriceAssertion
/// @notice Monitors Euler vault share prices and ensures they don't decrease unless bad debt socialization occurs
/// @dev This assertion intercepts EVC calls to monitor all vault interactions and validates
///      that vault share prices don't decrease unless bad debt socialization has occurred.
///
///      IMPORTANT: This assertion uses Euler's exchange rate formula which includes VIRTUAL_DEPOSIT_AMOUNT (1e6)
///      to prevent exchange rate manipulation attacks (first depositor attack). The formula is:
///      exchangeRate = (totalAssets + VIRTUAL_DEPOSIT) / (totalSupply + VIRTUAL_DEPOSIT)
///
/// @custom:invariant VAULT_SHARE_PRICE_INVARIANT
/// For any Euler vault V and any transaction T that interacts with V:
///
/// Let:
/// - SP_pre(V) = (totalAssets(V) + 1e6) * 1e18 / (totalSupply(V) + 1e6) before transaction T
/// - SP_post(V) = (totalAssets(V) + 1e6) * 1e18 / (totalSupply(V) + 1e6) after transaction T
/// - BAD_DEBT(T,V) = true if bad debt socialization events occurred for vault V in transaction T
///
/// Then the following invariant must hold:
///
/// SP_post(V) >= SP_pre(V) ∨ BAD_DEBT(T,V)
///
/// In plain English:
/// "An Euler vault's share price cannot decrease unless bad debt socialization has occurred"
///
/// Bad debt socialization is detected by monitoring the following events from vault V:
/// 1. DebtSocialized(account, assets) - explicit bad debt socialization event
/// 2. Repay(account, assets) where account ≠ address(0) AND Withdraw from address(0) - legacy bad debt pattern
///
/// This invariant protects depositors from:
/// - Malicious vault implementations that steal funds
/// - Protocol bugs that cause unexpected share price decreases
/// - Economic attacks that drain vault value
///
/// While allowing legitimate scenarios:
/// - Normal vault operations (deposits, withdrawals, yield)
/// - Bad debt socialization (as designed in Euler protocol)
contract VaultSharePriceAssertion is Assertion {
    /// @notice Virtual deposit amount used by Euler to prevent exchange rate manipulation
    /// @dev Per EVK ConversionHelpers.sol: "virtual deposit used in conversions between shares and assets,
    ///      serving as exchange rate manipulation mitigation"
    uint256 internal constant VIRTUAL_DEPOSIT_AMOUNT = 1e6;

    /// @notice Array of perspectives to check for vault verification
    /// @dev Includes GovernedPerspective and EscrowedCollateralPerspective
    IPerspective[] public perspectives;

    /// @notice Constructor to set the perspectives for vault verification
    /// @param _perspectives Array of perspective contract addresses
    constructor(
        address[] memory _perspectives
    ) {
        for (uint256 i = 0; i < _perspectives.length; i++) {
            perspectives.push(IPerspective(_perspectives[i]));
        }
    }

    /// @notice Checks if vault is verified in any of the perspectives
    /// @param vault The vault address to check
    /// @return True if the vault is verified in at least one perspective, or if no perspectives configured
    function isVerifiedVault(
        address vault
    ) internal view returns (bool) {
        // If no perspectives configured, verify all vaults (for testing compatibility)
        if (perspectives.length == 0) return true;

        for (uint256 i = 0; i < perspectives.length; i++) {
            try perspectives[i].isVerified(vault) returns (bool verified) {
                if (verified) return true;
            } catch {
                // Perspective call failed, skip this perspective
                continue;
            }
        }
        return false;
    }

    /// @notice Register triggers for EVC operations
    function triggers() external view override {
        // Register triggers for each call type
        registerCallTrigger(this.assertionBatchSharePriceInvariant.selector, IEVC.batch.selector);
        registerCallTrigger(this.assertionCallSharePriceInvariant.selector, IEVC.call.selector);
        registerCallTrigger(
            this.assertionControlCollateralSharePriceInvariant.selector, IEVC.controlCollateral.selector
        );
    }

    /// @notice Validates share price invariant for batch operations
    /// @dev Compares vault share prices before/after transaction. Reverts if share price decreases without
    /// bad debt socialization
    function assertionBatchSharePriceInvariant() external {
        IEVC evc = IEVC(ph.getAssertionAdopter());

        // Get all batch calls to analyze
        PhEvm.CallInputs[] memory batchCalls = ph.getCallInputs(address(evc), IEVC.batch.selector);

        // Process all batch calls to ensure complete coverage
        for (uint256 i = 0; i < batchCalls.length; i++) {
            // Decode batch call parameters directly: (BatchItem[] items)
            IEVC.BatchItem[] memory items = abi.decode(batchCalls[i].input, (IEVC.BatchItem[]));

            // Process all vaults in this batch call
            for (uint256 j = 0; j < items.length; j++) {
                address vault = items[j].targetContract;

                // Skip non-verified vaults (filters out WETH, Permit2, routers, EOAs, etc.)
                if (!isVerifiedVault(vault)) continue;

                validateVaultSharePriceInvariant(vault);
            }
        }
    }

    /// @notice Validates share price invariant for call operations
    /// @dev Compares vault share prices before/after transaction. Reverts if share price decreases without bad debt
    /// socialization
    function assertionCallSharePriceInvariant() external {
        IEVC evc = IEVC(ph.getAssertionAdopter());

        // Get all single calls to analyze
        PhEvm.CallInputs[] memory singleCalls = ph.getCallInputs(address(evc), IEVC.call.selector);

        // Process all single calls to ensure complete coverage
        for (uint256 i = 0; i < singleCalls.length; i++) {
            // Decode call parameters directly: (address targetContract, address onBehalfOfAccount, uint256 value, bytes
            // data)
            (address targetContract,,,) = abi.decode(singleCalls[i].input, (address, address, uint256, bytes));

            // Skip non-verified vaults
            if (!isVerifiedVault(targetContract)) continue;

            // Validate share price for the target contract (vault)
            validateVaultSharePriceInvariant(targetContract);
        }
    }

    /// @notice Validates share price invariant for controlCollateral operations
    /// @dev Compares vault share prices before/after transaction. Reverts if share price decreases without bad debt
    /// socialization
    function assertionControlCollateralSharePriceInvariant() external {
        IEVC evc = IEVC(ph.getAssertionAdopter());

        // Get all control collateral calls to analyze
        PhEvm.CallInputs[] memory controlCalls = ph.getCallInputs(address(evc), IEVC.controlCollateral.selector);

        // Process all control collateral calls to ensure complete coverage
        for (uint256 i = 0; i < controlCalls.length; i++) {
            // Decode control collateral parameters directly: (address targetCollateral, address onBehalfOfAccount,
            // uint256 value, bytes data)
            (address targetCollateral,,,) = abi.decode(controlCalls[i].input, (address, address, uint256, bytes));

            // Skip non-verified vaults
            if (!isVerifiedVault(targetCollateral)) continue;

            // Validate share price for the target collateral (vault)
            validateVaultSharePriceInvariant(targetCollateral);
        }
    }

    /// @notice Validates share price invariant for a vault
    /// @param vault The vault address to validate
    function validateVaultSharePriceInvariant(
        address vault
    ) internal {
        // Get pre-transaction share price
        ph.forkPreTx();
        uint256 preSharePrice = getSharePrice(vault);

        // Get post-transaction share price
        ph.forkPostTx();
        uint256 postSharePrice = getSharePrice(vault);

        // Check if share price decreased
        if (postSharePrice < preSharePrice) {
            // Share price decreased - check if bad debt socialization occurred
            bool hasBadDebtSocialization = checkForBadDebtSocialization(vault);

            require(
                hasBadDebtSocialization,
                "VaultSharePriceAssertion: Share price decreased without bad debt socialization"
            );
        }
    }

    /// @notice Gets the share price of an Euler vault using the EVK exchange rate formula
    /// @param vault The vault address
    /// @return sharePrice The share price using Euler's formula: (totalAssets + VD) * 1e18 / (totalSupply + VD)
    /// @dev Uses VIRTUAL_DEPOSIT_AMOUNT (1e6) as per EVK ConversionHelpers.sol to match Euler's internal
    ///      exchange rate calculation and prevent false positives from exchange rate manipulation protection.
    function getSharePrice(
        address vault
    ) internal view returns (uint256 sharePrice) {
        uint256 totalAssets = IERC4626(vault).totalAssets();
        uint256 totalSupply = IERC4626(vault).totalSupply();

        // Calculate share price using Euler's formula with VIRTUAL_DEPOSIT_AMOUNT
        // This matches EVK's ConversionHelpers.conversionTotals() which adds VIRTUAL_DEPOSIT_AMOUNT
        // to both totalAssets and totalShares to prevent exchange rate manipulation
        sharePrice = ((totalAssets + VIRTUAL_DEPOSIT_AMOUNT) * 1e18) / (totalSupply + VIRTUAL_DEPOSIT_AMOUNT);
    }

    /// @notice Checks if bad debt socialization occurred for a vault
    /// @param vault The vault address to check
    /// @return hasBadDebt True if DebtSocialized event or Repay+Withdraw bad debt pattern detected
    function checkForBadDebtSocialization(
        address vault
    ) internal returns (bool hasBadDebt) {
        // Get all logs from the transaction
        PhEvm.Log[] memory logs = ph.getLogs();

        bool hasDebtSocializedEvent = false;
        bool hasRepayFromLiquidator = false;
        bool hasWithdrawFromZero = false;

        // Event signatures
        bytes32 debtSocializedEventSig = keccak256("DebtSocialized(address,uint256)");
        bytes32 repayEventSig = keccak256("Repay(address,uint256)");
        bytes32 withdrawEventSig = keccak256("Withdraw(address,address,address,uint256,uint256)");

        // Check each log for legitimate share price decrease events
        for (uint256 i = 0; i < logs.length; i++) {
            PhEvm.Log memory log = logs[i];

            // Check if this log is from our vault
            if (log.emitter == vault) {
                if (log.topics.length >= 1) {
                    bytes32 eventSig = log.topics[0];

                    // Check for DebtSocialized event
                    if (eventSig == debtSocializedEventSig) {
                        hasDebtSocializedEvent = true;
                    }

                    // Check for Repay event
                    if (log.topics.length >= 2 && eventSig == repayEventSig) {
                        // Check if repay comes from a liquidator (not address(0))
                        address account = address(uint160(uint256(log.topics[1])));
                        if (account != address(0)) {
                            hasRepayFromLiquidator = true;
                        }
                    }

                    // Check for Withdraw event
                    if (log.topics.length >= 4 && eventSig == withdrawEventSig) {
                        // Check if withdraw appears to come from address(0) (sender is address(0))
                        address sender = address(uint160(uint256(log.topics[1])));
                        if (sender == address(0)) {
                            hasWithdrawFromZero = true;
                        }
                    }
                }
            }
        }

        // Bad debt socialization is detected if:
        // 1. DebtSocialized event is present (explicit bad debt socialization), OR
        // 2. Both Repay from liquidator AND Withdraw from address(0) occur together (legacy bad debt pattern)
        return hasDebtSocializedEvent || (hasRepayFromLiquidator && hasWithdrawFromZero);
    }
}
