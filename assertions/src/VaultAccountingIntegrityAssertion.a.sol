// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Assertion} from "credible-std/Assertion.sol";
import {PhEvm} from "credible-std/PhEvm.sol";
import {IEVC} from "../../src/interfaces/IEthereumVaultConnector.sol";
import {IERC4626} from "lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol";
import {IPerspective} from "./interfaces/IPerspective.sol";

/// @notice Interface for querying ERC20 token balances
interface IERC20 {
    function balanceOf(
        address account
    ) external view returns (uint256);
}

/// @notice Interface for EVault cash accounting
interface IEVaultCash {
    function cash() external view returns (uint256);
}

/// @title VaultAccountingIntegrityAssertion
/// @notice Ensures a vault's actual asset balance is at least its internal cash accounting
/// @dev This assertion monitors vault balance vs cash to detect unauthorized asset extraction
///      or accounting bugs where assets leave without cash being decremented.
///
/// @custom:invariant VAULT_ACCOUNTING_INTEGRITY_INVARIANT
/// For any vault V and any transaction T that interacts with V:
///
/// Let:
/// - asset = V.asset()
/// - balance = asset.balanceOf(V) after transaction T
/// - cash = V.cash() after transaction T
///
/// Then the following invariant must hold:
///    balance >= cash
///
/// In plain English:
/// "The vault's actual token balance must always be at least what it claims to have as cash"
///
/// This invariant protects against:
/// - Asset theft where tokens leave the vault without cash being decremented
/// - Accounting bugs where cash is inflated without corresponding tokens
/// - Implementation errors in withdrawal logic that fail to update cash
/// - Unauthorized asset extraction without proper accounting updates
/// - Exploits that transfer assets out while leaving cash unchanged
///
/// While allowing legitimate scenarios:
/// - Normal deposits (balance and cash both increase)
/// - Normal withdrawals (balance and cash both decrease, balance remains >= cash)
/// - Borrows (balance and cash both decrease by same amount, balance remains >= cash)
/// - Repays (balance and cash both increase by same amount)
/// - Donations to vault (balance > cash is acceptable - unaccounted assets can be claimed via skim())
contract VaultAccountingIntegrityAssertion is Assertion {
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
        registerCallTrigger(this.assertionBatchAccountingIntegrity.selector, IEVC.batch.selector);
        registerCallTrigger(this.assertionCallAccountingIntegrity.selector, IEVC.call.selector);
        registerCallTrigger(
            this.assertionControlCollateralAccountingIntegrity.selector, IEVC.controlCollateral.selector
        );
    }

    /// @notice Validates accounting integrity for batch operations
    /// @dev Validates each unique vault in batch once
    function assertionBatchAccountingIntegrity() external {
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
                validateVaultAccountingIntegrity(vault);
            }
        }
    }

    /// @notice Validates accounting integrity for call operations
    /// @dev Validates target contract from call parameters
    function assertionCallAccountingIntegrity() external {
        IEVC evc = IEVC(ph.getAssertionAdopter());
        PhEvm.CallInputs[] memory callInputs = ph.getCallInputs(address(evc), IEVC.call.selector);

        for (uint256 i = 0; i < callInputs.length; i++) {
            (address targetContract,,,,) = abi.decode(callInputs[i].input, (address, address, uint256, bytes, uint256));

            // Skip non-verified vaults
            if (!isVerifiedVault(targetContract)) continue;

            validateVaultAccountingIntegrity(targetContract);
        }
    }

    /// @notice Validates accounting integrity for controlCollateral operations
    /// @dev Validates target collateral from controlCollateral parameters
    function assertionControlCollateralAccountingIntegrity() external {
        IEVC evc = IEVC(ph.getAssertionAdopter());
        PhEvm.CallInputs[] memory controlInputs = ph.getCallInputs(address(evc), IEVC.controlCollateral.selector);

        for (uint256 i = 0; i < controlInputs.length; i++) {
            // controlCollateral signature: (address targetCollateral, address onBehalfOfAccount, uint256 value, bytes
            // data)
            (address targetCollateral,,,) = abi.decode(controlInputs[i].input, (address, address, uint256, bytes));

            // Skip non-verified vaults
            if (!isVerifiedVault(targetCollateral)) continue;

            validateVaultAccountingIntegrity(targetCollateral);
        }
    }

    /// @notice Validates vault's actual balance >= internal cash accounting
    /// @param vault The vault address to validate
    function validateVaultAccountingIntegrity(
        address vault
    ) internal {
        // Fork to post-transaction state and check: balance >= cash
        ph.forkPostTx();

        // Get asset and cash - vault is verified so these should succeed
        address asset = IERC4626(vault).asset();
        uint256 cash = IEVaultCash(vault).cash();
        uint256 balance = IERC20(asset).balanceOf(vault);

        require(balance >= cash, "VaultAccountingIntegrityAssertion: Balance < cash");
    }
}
