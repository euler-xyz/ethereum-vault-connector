// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Assertion} from "credible-std/Assertion.sol";
import {PhEvm} from "credible-std/PhEvm.sol";
import {IEVC} from "../../src/interfaces/IEthereumVaultConnector.sol";
import {IERC4626} from "lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol";
import {IPerspective} from "./interfaces/IPerspective.sol";

/// @title VaultExchangeRateSpikeAssertion
/// @notice Prevents the vault's exchange rate from changing by more than 5% in a single transaction
/// @dev This assertion monitors exchange rate changes to detect donation attacks, flash loan manipulation,
///      and other exploits that cause sudden rate spikes.
///
/// @custom:invariant VAULT_EXCHANGE_RATE_SPIKE_INVARIANT
/// For any vault V and any transaction T that interacts with V:
///
/// Let:
/// - totalAssets_pre = V.totalAssets() before transaction T
/// - totalSupply_pre = V.totalSupply() before transaction T
/// - totalAssets_post = V.totalAssets() after transaction T
/// - totalSupply_post = V.totalSupply() after transaction T
/// - exchangeRate_pre = totalAssets_pre * 1e18 / totalSupply_pre
/// - exchangeRate_post = totalAssets_post * 1e18 / totalSupply_post
/// - changePct = |exchangeRate_post - exchangeRate_pre| * 10000 / exchangeRate_pre (in basis points)
///
/// Then the following invariant must hold:
///    changePct <= 500 (5%)
///
/// In plain English:
/// "The exchange rate cannot suddenly change by more than 5% in a single transaction"
///
/// This invariant protects against:
/// - Donation attacks where attackers manipulate share price via large deposits
/// - Flash loan price manipulation attacks
/// - Accounting bugs that cause sudden rate changes
/// - Exploits that drain value from existing depositors
/// - Economic attacks via rate manipulation
///
/// While allowing legitimate scenarios:
/// - Normal interest accrual (gradual rate increases)
/// - Small rate fluctuations from deposits/withdrawals
/// - Debt socialization (sudden decreases when bad debt is socialized)
///
/// Note: This complements VaultSharePriceAssertion (#1):
/// - VaultSharePriceAssertion: Prevents decreases (except bad debt)
/// - VaultExchangeRateSpikeAssertion: Prevents large changes in EITHER direction
contract VaultExchangeRateSpikeAssertion is Assertion {
    /// @notice Maximum allowed exchange rate change in basis points (5% = 500 bps)
    uint256 constant THRESHOLD_BPS = 500;

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

    /// @notice Specifies which EVC functions this assertion should intercept
    /// @dev Registers triggers for batch, call, and controlCollateral operations
    function triggers() external view override {
        registerCallTrigger(this.assertionBatchExchangeRateSpike.selector, IEVC.batch.selector);
        registerCallTrigger(this.assertionCallExchangeRateSpike.selector, IEVC.call.selector);
        registerCallTrigger(this.assertionControlCollateralExchangeRateSpike.selector, IEVC.controlCollateral.selector);
    }

    /// @notice Validates exchange rate changes for batch operations
    /// @dev Validates each unique vault in batch once
    function assertionBatchExchangeRateSpike() external {
        IEVC evc = IEVC(ph.getAssertionAdopter());
        PhEvm.CallInputs[] memory batchCalls = ph.getCallInputs(address(evc), IEVC.batch.selector);

        // Collect all vaults from all batch calls
        uint256 totalItems = 0;
        for (uint256 i = 0; i < batchCalls.length; i++) {
            IEVC.BatchItem[] memory items = abi.decode(batchCalls[i].input, (IEVC.BatchItem[]));
            totalItems += items.length;
        }

        // Pre-allocate array for all possible vaults
        address[] memory allVaults = new address[](totalItems);
        uint256 vaultIndex = 0;

        // Collect all vault addresses
        for (uint256 i = 0; i < batchCalls.length; i++) {
            IEVC.BatchItem[] memory items = abi.decode(batchCalls[i].input, (IEVC.BatchItem[]));

            for (uint256 j = 0; j < items.length; j++) {
                address vault = items[j].targetContract;

                // Skip non-verified vaults (filters out WETH, Permit2, routers, EOAs, etc.)
                if (!isVerifiedVault(vault)) continue;

                allVaults[vaultIndex] = vault;
                vaultIndex++;
            }
        }

        // Validate each unique vault (deduplicate inline during validation)
        for (uint256 i = 0; i < vaultIndex; i++) {
            address vault = allVaults[i];

            // Skip if this vault was already checked (simple forward scan for deduplication)
            bool alreadyChecked = false;
            for (uint256 j = 0; j < i; j++) {
                if (allVaults[j] == vault) {
                    alreadyChecked = true;
                    break;
                }
            }

            if (!alreadyChecked) {
                validateVaultExchangeRateSpike(vault);
            }
        }
    }

    /// @notice Validates exchange rate changes for call operations
    /// @dev Validates target contract from call parameters
    function assertionCallExchangeRateSpike() external {
        IEVC evc = IEVC(ph.getAssertionAdopter());
        PhEvm.CallInputs[] memory callInputs = ph.getCallInputs(address(evc), IEVC.call.selector);

        for (uint256 i = 0; i < callInputs.length; i++) {
            (address targetContract,,,,) = abi.decode(callInputs[i].input, (address, address, uint256, bytes, uint256));

            // Skip non-verified vaults
            if (!isVerifiedVault(targetContract)) continue;

            validateVaultExchangeRateSpike(targetContract);
        }
    }

    /// @notice Validates exchange rate changes for controlCollateral operations
    /// @dev Validates target collateral from controlCollateral parameters
    function assertionControlCollateralExchangeRateSpike() external {
        IEVC evc = IEVC(ph.getAssertionAdopter());
        PhEvm.CallInputs[] memory controlInputs = ph.getCallInputs(address(evc), IEVC.controlCollateral.selector);

        for (uint256 i = 0; i < controlInputs.length; i++) {
            // controlCollateral signature: (address targetCollateral, address onBehalfOfAccount, uint256 value, bytes
            // data)
            (address targetCollateral,,,) = abi.decode(controlInputs[i].input, (address, address, uint256, bytes));

            // Skip non-verified vaults
            if (!isVerifiedVault(targetCollateral)) continue;

            validateVaultExchangeRateSpike(targetCollateral);
        }
    }

    /// @notice Validates vault's exchange rate change is within 5% threshold
    /// @dev Allows rate decreases >5% when debt socialization occurs
    /// @param vault The vault address to validate
    function validateVaultExchangeRateSpike(
        address vault
    ) internal {
        // Skip zero address
        if (vault == address(0)) return;

        // Get pre-transaction exchange rate
        ph.forkPreTx();
        (uint256 ratePre, bool validPre) = getExchangeRate(vault);
        if (!validPre) return; // Skip if not a valid ERC4626 vault or empty vault

        // Get post-transaction exchange rate
        ph.forkPostTx();
        (uint256 ratePost, bool validPost) = getExchangeRate(vault);
        if (!validPost) return; // Skip if vault became empty

        // Calculate absolute percentage change in basis points
        uint256 changeBps;
        bool isDecrease = false;
        if (ratePost >= ratePre) {
            // Rate increased
            changeBps = ((ratePost - ratePre) * 10000) / ratePre;
        } else {
            // Rate decreased
            changeBps = ((ratePre - ratePost) * 10000) / ratePre;
            isDecrease = true;
        }

        // If rate decreased >5%, check if it's due to debt socialization
        if (isDecrease && changeBps > THRESHOLD_BPS) {
            bool hasDebtSocialization = checkForBadDebtSocialization(vault);
            require(
                hasDebtSocialization,
                "VaultExchangeRateSpikeAssertion: Exchange rate decreased >5% without debt socialization"
            );
        } else {
            // For increases or small decreases, enforce the threshold
            require(changeBps <= THRESHOLD_BPS, "VaultExchangeRateSpikeAssertion: Exchange rate spike detected");
        }
    }

    /// @notice Gets the exchange rate for a vault (assets per share, scaled by 1e18)
    /// @param vault The vault address to query
    /// @return rate The exchange rate scaled by 1e18
    /// @return valid Whether the rate is valid (false if totalSupply is 0)
    function getExchangeRate(
        address vault
    ) internal view returns (uint256 rate, bool valid) {
        uint256 totalAssets = IERC4626(vault).totalAssets();
        uint256 totalSupply = IERC4626(vault).totalSupply();

        // Empty vault - skip
        if (totalSupply == 0) {
            return (0, false);
        }

        // Calculate exchange rate: totalAssets * 1e18 / totalSupply
        rate = (totalAssets * 1e18) / totalSupply;
        return (rate, true);
    }

    /// @notice Checks if bad debt socialization occurred for a vault
    /// @param vault The vault address to check
    /// @return hasBadDebt True if bad debt socialization was detected via DebtSocialized event
    ///
    /// BAD DEBT SOCIALIZATION DETECTION:
    /// Checks for the DebtSocialized event which indicates that bad debt was socialized among depositors.
    /// This is a legitimate reason for the exchange rate to suddenly decrease.
    function checkForBadDebtSocialization(
        address vault
    ) internal returns (bool hasBadDebt) {
        // Get all logs from the transaction
        PhEvm.Log[] memory logs = ph.getLogs();

        // Check each log for DebtSocialized event from this vault
        for (uint256 i = 0; i < logs.length; i++) {
            PhEvm.Log memory log = logs[i];

            // Check if this log is from our vault
            if (log.emitter == vault) {
                // Check for DebtSocialized event (topic[0] = event signature)
                // DebtSocialized event signature: keccak256("DebtSocialized(address,uint256)")
                if (log.topics.length >= 1) {
                    bytes32 debtSocializedEventSig = keccak256("DebtSocialized(address,uint256)");
                    if (log.topics[0] == debtSocializedEventSig) {
                        return true;
                    }
                }
            }
        }

        return false;
    }
}
