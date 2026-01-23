// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Assertion} from "credible-std/Assertion.sol";
import {PhEvm} from "credible-std/PhEvm.sol";
import {IEVC} from "../../src/interfaces/IEthereumVaultConnector.sol";
import {IVault} from "../../src/interfaces/IVault.sol";
import {IERC4626} from "lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol";
import {IPerspective} from "./interfaces/IPerspective.sol";

/// @title VaultAssetTransferAccountingAssertion
/// @notice Ensures all asset transfers from vaults are properly accounted for by Withdraw, Borrow, or Deposit events
/// @dev This assertion monitors event logs to validate that every asset token transfer leaving a vault
///      is accompanied by a corresponding Withdraw, Borrow, or Deposit-to-underlying event with matching amount.
///
/// @custom:invariant VAULT_ASSET_TRANSFER_ACCOUNTING_INVARIANT
/// For any vault V, any transaction T, and the asset token A = V.asset():
///
/// Let:
/// - transferEvents = all Transfer(address from, address to, uint256 amount) events
///                    emitted by A where from == V in transaction T
/// - withdrawEvents = all Withdraw(address sender, address receiver, address owner,
///                                 uint256 assets, uint256 shares) events
///                    emitted by V in transaction T
/// - borrowEvents = all Borrow(address account, uint256 assets) events
///                  emitted by V in transaction T
/// - depositToUnderlyingEvents = all Deposit(address sender, address owner, uint256 assets, uint256 shares) events
///                               emitted by ANY contract where sender == V OR owner == V in transaction T
///                               (this captures nested vault deposits and yield strategy deposits)
/// - totalTransferred = sum of all amounts in transferEvents
/// - totalWithdrawn = sum of all assets in withdrawEvents
/// - totalBorrowed = sum of all assets in borrowEvents
/// - totalDepositedToUnderlying = sum of all assets in depositToUnderlyingEvents
/// - totalAccounted = totalWithdrawn + totalBorrowed + totalDepositedToUnderlying
///
/// Then the following invariant must hold:
/// totalTransferred <= totalAccounted
///
/// In plain English:
/// "Every asset token that leaves the vault must be accounted for by a Withdraw, Borrow, or Deposit-to-underlying
/// event"
///
/// This invariant protects against:
/// - Unauthorized asset extraction without proper event emission
/// - Exploits that bypass normal withdrawal/borrow flows
/// - Implementation bugs where assets are transferred without events
/// - Malicious vault code that silently drains funds
/// - Accounting bypasses that don't update internal state properly
///
/// While allowing legitimate scenarios:
/// - Normal withdrawals with Withdraw events
/// - Normal borrows with Borrow events
/// - Nested vault deposits (wrapper vaults depositing into underlying yield vaults)
/// - Yield strategy rebalancing (vault moving assets between strategies)
/// - Multiple operations in same transaction (sum of all transfers matched against sum of all events)
/// - Flash loans (assets transferred out and returned in same tx, net should match events)
///
/// Note: This assertion only monitors transfers OUT of vaults (where from == vault).
/// Transfers INTO vaults (deposits, repayments) are not monitored by this assertion.
contract VaultAssetTransferAccountingAssertion is Assertion {
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
        registerCallTrigger(this.assertionBatchAssetTransferAccounting.selector, IEVC.batch.selector);
        registerCallTrigger(this.assertionCallAssetTransferAccounting.selector, IEVC.call.selector);
        registerCallTrigger(
            this.assertionControlCollateralAssetTransferAccounting.selector, IEVC.controlCollateral.selector
        );
    }

    /// @notice Validates asset transfer accounting for batch operations
    /// @dev Validates each unique vault in batch once
    function assertionBatchAssetTransferAccounting() external {
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
                validateVaultAssetTransferAccounting(vault);
            }
        }
    }

    /// @notice Validates asset transfer accounting for call operations
    /// @dev Validates target contract from call parameters
    function assertionCallAssetTransferAccounting() external {
        IEVC evc = IEVC(ph.getAssertionAdopter());
        PhEvm.CallInputs[] memory callInputs = ph.getCallInputs(address(evc), IEVC.call.selector);

        for (uint256 i = 0; i < callInputs.length; i++) {
            (address targetContract,,,,) = abi.decode(callInputs[i].input, (address, address, uint256, bytes, uint256));

            // Skip non-verified vaults
            if (!isVerifiedVault(targetContract)) continue;

            validateVaultAssetTransferAccounting(targetContract);
        }
    }

    /// @notice Validates asset transfer accounting for controlCollateral operations
    /// @dev Validates target collateral from controlCollateral parameters
    function assertionControlCollateralAssetTransferAccounting() external {
        IEVC evc = IEVC(ph.getAssertionAdopter());
        PhEvm.CallInputs[] memory controlInputs = ph.getCallInputs(address(evc), IEVC.controlCollateral.selector);

        for (uint256 i = 0; i < controlInputs.length; i++) {
            // controlCollateral signature: (address targetCollateral, address onBehalfOfAccount, uint256 value, bytes
            // data)
            (address targetCollateral,,,) = abi.decode(controlInputs[i].input, (address, address, uint256, bytes));

            // Skip non-verified vaults
            if (!isVerifiedVault(targetCollateral)) continue;

            validateVaultAssetTransferAccounting(targetCollateral);
        }
    }

    /// @notice Validates all asset transfers are accounted for by Withdraw, Borrow, or Deposit-to-underlying events
    /// @param vault The vault address to validate
    function validateVaultAssetTransferAccounting(
        address vault
    ) internal {
        // Get the asset token address for this vault
        address asset = IERC4626(vault).asset();

        // Get all logs from the transaction
        PhEvm.Log[] memory logs = ph.getLogs();

        // Event signatures
        bytes32 transferEventSig = keccak256("Transfer(address,address,uint256)");
        bytes32 withdrawEventSig = keccak256("Withdraw(address,address,address,uint256,uint256)");
        bytes32 borrowEventSig = keccak256("Borrow(address,uint256)");
        bytes32 depositEventSig = keccak256("Deposit(address,address,uint256,uint256)");

        uint256 totalTransferred = 0;
        uint256 totalWithdrawn = 0;
        uint256 totalBorrowed = 0;
        uint256 totalDepositedToUnderlying = 0;

        // Parse all logs and sum amounts
        for (uint256 i = 0; i < logs.length; i++) {
            PhEvm.Log memory log = logs[i];

            // Check Transfer events from asset token where from == vault
            if (log.emitter == asset && log.topics.length >= 3) {
                if (log.topics[0] == transferEventSig) {
                    address from = address(uint160(uint256(log.topics[1])));
                    if (from == vault) {
                        // Transfer amount is in data field for ERC20 Transfer events
                        uint256 amount = abi.decode(log.data, (uint256));
                        totalTransferred += amount;
                    }
                }
            }

            // Check Withdraw events from vault
            // Withdraw(address indexed sender, address indexed receiver, address indexed owner, uint256 assets, uint256
            // shares)
            if (log.emitter == vault && log.topics.length >= 4) {
                if (log.topics[0] == withdrawEventSig) {
                    // Assets and shares are in data field
                    (uint256 assets,) = abi.decode(log.data, (uint256, uint256));
                    totalWithdrawn += assets;
                }
            }

            // Check Borrow events from vault
            // Borrow(address indexed account, uint256 assets)
            if (log.emitter == vault && log.topics.length >= 2) {
                if (log.topics[0] == borrowEventSig) {
                    // Assets amount is in data field
                    uint256 assets = abi.decode(log.data, (uint256));
                    totalBorrowed += assets;
                }
            }

            // Check Deposit events where vault deposited to ANOTHER vault (nested vault pattern)
            // Deposit(address indexed sender, address indexed owner, uint256 assets, uint256 shares)
            // This captures: wrapper vaults depositing into underlying yield vaults,
            // yield strategy rebalancing, and similar legitimate asset movements
            if (log.emitter != vault && log.topics.length >= 3) {
                if (log.topics[0] == depositEventSig) {
                    address sender = address(uint160(uint256(log.topics[1])));
                    address owner = address(uint160(uint256(log.topics[2])));

                    // If our vault is the depositor (sender or owner), count as accounted
                    if (sender == vault || owner == vault) {
                        // Assets amount is first field in data
                        (uint256 assets,) = abi.decode(log.data, (uint256, uint256));
                        totalDepositedToUnderlying += assets;
                    }
                }
            }
        }

        // Validate invariant: totalTransferred <= totalWithdrawn + totalBorrowed + totalDepositedToUnderlying
        uint256 totalAccounted = totalWithdrawn + totalBorrowed + totalDepositedToUnderlying;
        require(
            totalTransferred <= totalAccounted,
            "VaultAssetTransferAccountingAssertion: Unaccounted asset transfers detected"
        );
    }
}
