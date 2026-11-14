// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Assertion} from "credible-std/Assertion.sol";
import {PhEvm} from "credible-std/PhEvm.sol";
import {IEVC} from "../../src/interfaces/IEthereumVaultConnector.sol";
import {IVault} from "../../src/interfaces/IVault.sol";
import {IPerspective} from "./interfaces/IPerspective.sol";

/// @title AccountHealthAssertion
/// @notice Monitors account health and ensures healthy accounts cannot become unhealthy through vault operations
/// @dev This assertion intercepts EVC calls to monitor all vault interactions and validates
///      that accounts that are healthy before a transaction remain healthy after the transaction.
///
/// ACCOUNT EXTRACTION STRATEGY:
/// Uses a hybrid approach to identify affected accounts:
/// 1. Extracts the onBehalfOfAccount from EVC calls (batch, call, controlCollateral)
/// 2. Parses vault function call data to extract additional accounts from parameters:
///    - withdraw(uint256,address,address) → owner (3rd param)
///    - redeem(uint256,address,address) → owner (3rd param)
///    - transferFrom(address,address,uint256) → from (1st param)
///    - borrow(uint256,address) → receiver (2nd param)
///    - repay(uint256,address) → debtor (2nd param)
///    - liquidate(address,address,uint256,uint256) → violator (1st param)
/// This ensures complete coverage of all potentially affected accounts.
///
/// @custom:invariant ACCOUNT_HEALTH_INVARIANT
/// For any account A, any vault V, and any transaction T that interacts with V:
///
/// Let:
/// - H_pre(A,V) = true if account A is healthy (collateralValue >= liabilityValue) before transaction T
/// - H_post(A,V) = true if account A is healthy after transaction T
///
/// Then the following invariant must hold:
///
/// H_pre(A,V) → H_post(A,V)
///
/// In plain English:
/// "If an account is healthy before a transaction, it must remain healthy after the transaction"
///
/// Account health is determined by:
/// 1. Calling the controller vault's checkAccountStatus() function (if available)
/// 2. Comparing collateralValue >= liabilityValue using accountLiquidity()
///
/// This invariant protects users from:
/// - Unauthorized liquidations
/// - Malicious vault operations that manipulate account health
/// - Protocol bugs that incorrectly decrease account health
/// - Collateral manipulation attacks
///
/// While allowing legitimate scenarios:
/// - Already unhealthy accounts can remain unhealthy or become healthy
/// - Healthy accounts can become healthier
/// - Normal vault operations that maintain or improve account health
///
/// CROSS-VAULT HEALTH IMPACT:
/// Operations on one vault CAN affect account health in controller vaults. When a collateral vault
/// is modified (e.g., withdraw reduces collateral), the controller vault's view of account health
/// changes because checkAccountStatus() receives all enabled collaterals and prices them together.
/// This assertion checks health at BOTH the touched vaults AND the controller vaults for all affected accounts.
///
/// TODO: Follow up on whether we should skip accounts with no position (zero collateral and liability)
contract AccountHealthAssertion is Assertion {
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
        registerCallTrigger(this.assertionBatchAccountHealth.selector, IEVC.batch.selector);
        registerCallTrigger(this.assertionCallAccountHealth.selector, IEVC.call.selector);
        registerCallTrigger(this.assertionControlCollateralAccountHealth.selector, IEVC.controlCollateral.selector);
    }

    /// @notice Validates account health for batch operations
    /// @dev Intercepts EVC batch calls and ensures healthy accounts remain healthy
    ///
    /// Account Identification:
    /// - onBehalfOfAccount from batch items
    /// - Additional accounts extracted from function parameters (withdraw owner, redeem owner,
    ///   transferFrom sender, borrow receiver, repay debtor, liquidate violator)
    ///
    /// Validation Strategy:
    /// - Collects all unique accounts and vaults from batch items
    /// - Validates each account once at touched vaults and their controller vaults
    /// - Checks health before/after transaction using checkAccountStatus()
    /// - Reverts if a healthy account becomes unhealthy
    ///
    /// Cross-Vault Health:
    /// Operations on collateral vaults affect controller vault health checks since
    /// checkAccountStatus() evaluates all enabled collaterals together
    function assertionBatchAccountHealth() external {
        IEVC evc = IEVC(ph.getAssertionAdopter());

        // Get all batch calls to analyze (including nested batches via delegatecall)
        PhEvm.CallInputs[] memory batchCalls = ph.getAllCallInputs(address(evc), IEVC.batch.selector);

        // Process all batch calls to ensure complete coverage
        for (uint256 i = 0; i < batchCalls.length; i++) {
            // Decode batch call parameters directly: (BatchItem[] items)
            IEVC.BatchItem[] memory items = abi.decode(batchCalls[i].input, (IEVC.BatchItem[]));

            // Collect unique accounts and vaults from all batch items
            address[] memory uniqueAccounts = new address[](items.length * 2); // Max 2 accounts per item
            uint256 uniqueCount = 0;
            address[] memory uniqueVaults = new address[](items.length);
            uint256 vaultCount = 0;

            for (uint256 j = 0; j < items.length;) {
                // Unwrap nested evc.call() operations
                // When batch items target EVC with call(), extract the real target vault and operation
                address targetContract = items[j].targetContract;
                bytes memory operationData = items[j].data;
                address onBehalfOf = items[j].onBehalfOfAccount;

                if (targetContract == address(evc) && items[j].data.length >= 4) {
                    bytes4 selector;
                    bytes memory itemData = items[j].data;
                    assembly {
                        selector := mload(add(itemData, 32))
                    }

                    // Check if this is an evc.call() operation (selector 0x1f8b5215)
                    if (selector == IEVC.call.selector) {
                        // Decode the full calldata including selector
                        // call(address targetContract, address onBehalfOfAccount, uint256 value, bytes data)
                        bytes memory fullData = items[j].data;
                        address nestedTarget;
                        address nestedOnBehalfOf;
                        bytes memory nestedData;

                        assembly {
                            // Skip 4 bytes (selector) + 32 bytes to get first param (targetContract)
                            nestedTarget := mload(add(fullData, 36))
                            // Skip 4 + 32 + 32 to get second param (onBehalfOfAccount)
                            nestedOnBehalfOf := mload(add(fullData, 68))
                            // Skip 4 + 32 + 32 + 32 to skip value, then read bytes data
                            // The bytes data is at offset 4 + 32*3 = 100, but it's a dynamic param
                            // so we need to read the offset pointer first
                            let dataOffset := add(fullData, add(4, mload(add(fullData, 132))))
                            let dataLength := mload(dataOffset)

                            // Allocate memory for nestedData
                            nestedData := mload(0x40)
                            mstore(0x40, add(nestedData, add(32, dataLength)))
                            mstore(nestedData, dataLength)

                            // Copy data
                            let src := add(dataOffset, 32)
                            let dst := add(nestedData, 32)
                            for { let copyIdx := 0 } lt(copyIdx, dataLength) { copyIdx := add(copyIdx, 32) } {
                                mstore(add(dst, copyIdx), mload(add(src, copyIdx)))
                            }
                        }

                        // Use the nested call's actual target and data
                        targetContract = nestedTarget;
                        operationData = nestedData;
                        // For nested calls, use the nested onBehalfOf (the authenticated account)
                        onBehalfOf = nestedOnBehalfOf;
                    } else if (selector == IEVC.batch.selector) {
                        // Nested batch via delegatecall: Skip here, will be processed by its own assertion run.
                        // getAllCallInputs() captures both external and delegatecall batches, so each batch
                        // (outer and inner) gets its own assertion run with complete validation.
                        unchecked {
                            ++j;
                        }
                        continue;
                    }
                }

                // Skip non-contract addresses
                if (targetContract.code.length == 0) {
                    unchecked {
                        ++j;
                    }
                    continue;
                }

                // Skip non-verified vaults (filters out WETH, Permit2, routers, etc.)
                if (!isVerifiedVault(targetContract)) {
                    unchecked {
                        ++j;
                    }
                    continue;
                }

                // Extract accounts affected by this operation (does selector check internally)
                address[] memory extractedAccounts = extractAccountsFromCalldata(operationData);

                // Early exit: if no accounts extracted, this is a non-monitored operation
                // (deposit, mint, transfer, etc.) - skip all further processing
                if (extractedAccounts.length == 0 && onBehalfOf == address(0)) {
                    unchecked {
                        ++j;
                    }
                    continue;
                }

                // Collect unique vaults (use unwrapped target)
                bool vaultFound = false;
                for (uint256 k = 0; k < vaultCount;) {
                    if (uniqueVaults[k] == targetContract) {
                        vaultFound = true;
                        break;
                    }
                    unchecked {
                        ++k;
                    }
                }
                if (!vaultFound) {
                    uniqueVaults[vaultCount++] = targetContract;
                }

                // Add onBehalfOfAccount if present and unique (use unwrapped onBehalfOf)
                if (onBehalfOf != address(0)) {
                    bool found = false;
                    for (uint256 k = 0; k < uniqueCount;) {
                        if (uniqueAccounts[k] == onBehalfOf) {
                            found = true;
                            break;
                        }
                        unchecked {
                            ++k;
                        }
                    }
                    if (!found) {
                        uniqueAccounts[uniqueCount++] = onBehalfOf;
                    }
                }

                // Add extracted accounts if unique
                for (uint256 m = 0; m < extractedAccounts.length;) {
                    if (extractedAccounts[m] != address(0)) {
                        bool found = false;
                        for (uint256 k = 0; k < uniqueCount;) {
                            if (uniqueAccounts[k] == extractedAccounts[m]) {
                                found = true;
                                break;
                            }
                            unchecked {
                                ++k;
                            }
                        }
                        if (!found) {
                            uniqueAccounts[uniqueCount++] = extractedAccounts[m];
                        }
                    }
                    unchecked {
                        ++m;
                    }
                }

                unchecked {
                    ++j;
                }
            }

            // Validate each unique account at touched vaults and controllers
            for (uint256 n = 0; n < uniqueCount; n++) {
                address account = uniqueAccounts[n];

                // Skip if this "account" is actually a vault address
                // Vaults don't have account health in the traditional sense - they manage user positions
                // Checking health of a vault address would result in unnecessary reverts
                bool isVault = false;
                for (uint256 v = 0; v < vaultCount; v++) {
                    if (uniqueVaults[v] == account) {
                        isVault = true;
                        break;
                    }
                }
                if (isVault) continue;

                // Check health at all touched vaults
                for (uint256 v = 0; v < vaultCount; v++) {
                    validateAccountHealthInvariant(uniqueVaults[v], account);
                }

                // Check health at all controller vaults for this account
                address[] memory controllers = evc.getControllers(account);

                for (uint256 k = 0; k < controllers.length; k++) {
                    address controller = controllers[k];
                    if (controller.code.length == 0) continue;

                    validateAccountHealthInvariant(controller, account);
                }
            }
        }
    }

    /// @notice Validates account health for single call operations
    /// @dev Intercepts EVC call operations and ensures healthy accounts remain healthy
    ///
    /// Skips calls nested within batch operations by checking areChecksDeferred flag
    /// using forkPreCall() to examine state at the exact moment the call executed.
    /// This prevents double validation since batch assertions handle nested operations.
    ///
    /// Validation ensures each operation is checked exactly once:
    /// - Top-level evc.call() → validated here
    /// - evc.batch() operations → validated by assertionBatchAccountHealth
    /// - Nested evc.call() within batch → skipped
    function assertionCallAccountHealth() external {
        IEVC evc = IEVC(ph.getAssertionAdopter());

        // Get all single calls to analyze
        PhEvm.CallInputs[] memory singleCalls = ph.getCallInputs(address(evc), IEVC.call.selector);

        // Collect unique accounts and vaults, filtering out nested calls
        address[] memory uniqueAccounts = new address[](singleCalls.length * 2); // Max 2 accounts per call
        uint256 uniqueCount = 0;
        address[] memory uniqueVaults = new address[](singleCalls.length);
        uint256 vaultCount = 0;

        for (uint256 i = 0; i < singleCalls.length;) {
            // Fork to state RIGHT BEFORE this specific call executed
            // This allows us to check if we were inside a batch at that moment
            ph.forkPreCall(singleCalls[i].id);

            // Skip this call if it was nested within a batch
            // The batch assertion will handle validation for these
            if (evc.areChecksDeferred()) {
                unchecked {
                    ++i;
                }
                continue;
            }

            // Decode call parameters
            (address targetContract, address onBehalfOfAccount,, bytes memory data) =
                abi.decode(singleCalls[i].input, (address, address, uint256, bytes));

            // Skip non-contract addresses
            if (targetContract.code.length == 0) {
                unchecked {
                    ++i;
                }
                continue;
            }

            // Skip non-verified vaults (filters out WETH, Permit2, routers, etc.)
            if (!isVerifiedVault(targetContract)) {
                unchecked {
                    ++i;
                }
                continue;
            }

            // Extract accounts affected by this operation (does selector check internally)
            address[] memory extractedAccounts = extractAccountsFromCalldata(data);

            // Early exit: if no accounts extracted, this is a non-monitored operation
            if (extractedAccounts.length == 0 && onBehalfOfAccount == address(0)) {
                unchecked {
                    ++i;
                }
                continue;
            }

            // Collect unique vault
            bool vaultFound = false;
            for (uint256 v = 0; v < vaultCount;) {
                if (uniqueVaults[v] == targetContract) {
                    vaultFound = true;
                    break;
                }
                unchecked {
                    ++v;
                }
            }
            if (!vaultFound) {
                uniqueVaults[vaultCount++] = targetContract;
            }

            // Add onBehalfOfAccount if unique
            if (onBehalfOfAccount != address(0)) {
                bool found = false;
                for (uint256 k = 0; k < uniqueCount;) {
                    if (uniqueAccounts[k] == onBehalfOfAccount) {
                        found = true;
                        break;
                    }
                    unchecked {
                        ++k;
                    }
                }
                if (!found) {
                    uniqueAccounts[uniqueCount++] = onBehalfOfAccount;
                }
            }

            // Add extracted accounts if unique
            for (uint256 m = 0; m < extractedAccounts.length;) {
                if (extractedAccounts[m] != address(0)) {
                    bool found = false;
                    for (uint256 k = 0; k < uniqueCount;) {
                        if (uniqueAccounts[k] == extractedAccounts[m]) {
                            found = true;
                            break;
                        }
                        unchecked {
                            ++k;
                        }
                    }
                    if (!found) {
                        uniqueAccounts[uniqueCount++] = extractedAccounts[m];
                    }
                }
                unchecked {
                    ++m;
                }
            }

            unchecked {
                ++i;
            }
        }

        // Validate each unique account at touched vaults and controllers
        for (uint256 n = 0; n < uniqueCount;) {
            address account = uniqueAccounts[n];

            // Check health at all touched vaults
            for (uint256 v = 0; v < vaultCount;) {
                validateAccountHealthInvariant(uniqueVaults[v], account);
                unchecked {
                    ++v;
                }
            }

            // Check health at all controller vaults
            address[] memory controllers = evc.getControllers(account);

            for (uint256 k = 0; k < controllers.length;) {
                address controller = controllers[k];
                if (controller.code.length != 0) {
                    validateAccountHealthInvariant(controller, account);
                }
                unchecked {
                    ++k;
                }
            }

            unchecked {
                ++n;
            }
        }
    }

    /// @notice Validates account health for control collateral operations
    /// @dev Intercepts EVC controlCollateral calls and ensures healthy accounts remain healthy
    ///
    /// Skips calls nested within batch operations by checking areChecksDeferred flag
    /// using forkPreCall() to examine state at the exact moment the call executed.
    function assertionControlCollateralAccountHealth() external {
        IEVC evc = IEVC(ph.getAssertionAdopter());

        // Get all control collateral calls to analyze
        PhEvm.CallInputs[] memory controlCalls = ph.getCallInputs(address(evc), IEVC.controlCollateral.selector);

        // Collect unique accounts and vaults, filtering out nested calls
        address[] memory uniqueAccounts = new address[](controlCalls.length * 2); // Max 2 accounts per call
        uint256 uniqueCount = 0;
        address[] memory uniqueVaults = new address[](controlCalls.length);
        uint256 vaultCount = 0;

        for (uint256 i = 0; i < controlCalls.length;) {
            // Fork to state RIGHT BEFORE this specific call executed
            // This allows us to check if we were inside a batch at that moment
            ph.forkPreCall(controlCalls[i].id);

            // Skip this call if it was nested within a batch
            // The batch assertion will handle validation for these
            if (evc.areChecksDeferred()) {
                unchecked {
                    ++i;
                }
                continue;
            }

            // Decode control collateral parameters
            (address targetCollateral, address onBehalfOfAccount,, bytes memory data) =
                abi.decode(controlCalls[i].input, (address, address, uint256, bytes));

            // Skip non-contract addresses
            if (targetCollateral.code.length == 0) {
                unchecked {
                    ++i;
                }
                continue;
            }

            // Skip non-verified vaults (filters out WETH, Permit2, routers, etc.)
            if (!isVerifiedVault(targetCollateral)) {
                unchecked {
                    ++i;
                }
                continue;
            }

            // Extract accounts affected by this operation (does selector check internally)
            address[] memory extractedAccounts = extractAccountsFromCalldata(data);

            // Early exit: if no accounts extracted, this is a non-monitored operation
            if (extractedAccounts.length == 0 && onBehalfOfAccount == address(0)) {
                unchecked {
                    ++i;
                }
                continue;
            }

            // Collect unique vault
            bool vaultFound = false;
            for (uint256 v = 0; v < vaultCount;) {
                if (uniqueVaults[v] == targetCollateral) {
                    vaultFound = true;
                    break;
                }
                unchecked {
                    ++v;
                }
            }
            if (!vaultFound) {
                uniqueVaults[vaultCount++] = targetCollateral;
            }

            // Add onBehalfOfAccount if unique
            if (onBehalfOfAccount != address(0)) {
                bool found = false;
                for (uint256 k = 0; k < uniqueCount;) {
                    if (uniqueAccounts[k] == onBehalfOfAccount) {
                        found = true;
                        break;
                    }
                    unchecked {
                        ++k;
                    }
                }
                if (!found) {
                    uniqueAccounts[uniqueCount++] = onBehalfOfAccount;
                }
            }

            // Add extracted accounts if unique
            for (uint256 m = 0; m < extractedAccounts.length;) {
                if (extractedAccounts[m] != address(0)) {
                    bool found = false;
                    for (uint256 k = 0; k < uniqueCount;) {
                        if (uniqueAccounts[k] == extractedAccounts[m]) {
                            found = true;
                            break;
                        }
                        unchecked {
                            ++k;
                        }
                    }
                    if (!found) {
                        uniqueAccounts[uniqueCount++] = extractedAccounts[m];
                    }
                }
                unchecked {
                    ++m;
                }
            }

            unchecked {
                ++i;
            }
        }

        // Validate each unique account at touched vaults and controllers
        for (uint256 n = 0; n < uniqueCount;) {
            address account = uniqueAccounts[n];

            // Check health at all touched collateral vaults
            for (uint256 v = 0; v < vaultCount;) {
                validateAccountHealthInvariant(uniqueVaults[v], account);
                unchecked {
                    ++v;
                }
            }

            // Check health at all controller vaults
            address[] memory controllers = evc.getControllers(account);

            for (uint256 k = 0; k < controllers.length;) {
                address controller = controllers[k];
                if (controller.code.length != 0) {
                    validateAccountHealthInvariant(controller, account);
                }
                unchecked {
                    ++k;
                }
            }

            unchecked {
                ++n;
            }
        }
    }

    /// @notice Validates the account health invariant for a specific vault and account
    /// @param vault The vault address to validate
    /// @param account The account address to validate
    /// @dev Compares account health before and after transaction. Reverts if a healthy
    ///      account becomes unhealthy. Skips non-contract addresses and already unhealthy accounts.
    function validateAccountHealthInvariant(
        address vault,
        address account
    ) internal {
        // Skip zero address
        if (account == address(0)) return;

        // Skip non-contract vaults
        if (vault.code.length == 0) return;

        // Check if vault implements IVault interface by verifying checkAccountStatus exists
        // This prevents expensive operations on non-vault contracts (e.g., WETH, ERC20s)
        if (!supportsCheckAccountStatus(vault)) return;

        // Get pre-transaction account health
        ph.forkPreTx();
        bool preHealthy = isAccountHealthy(vault, account);

        // Get post-transaction account health
        ph.forkPostTx();
        bool postHealthy = isAccountHealthy(vault, account);

        // If account was healthy before, it must remain healthy after
        if (preHealthy && !postHealthy) {
            require(false, "AccountHealthAssertion: Healthy account became unhealthy");
        }
    }

    /// @notice Checks if a contract implements checkAccountStatus function
    /// @param vault The address to check
    /// @return bool True if the contract implements checkAccountStatus
    /// @dev Uses a low-level staticcall to check function existence without executing it
    function supportsCheckAccountStatus(
        address vault
    ) internal view returns (bool) {
        // Prepare calldata for checkAccountStatus(address,address[])
        // We use empty arrays as parameters since we only care if the function exists
        bytes memory data = abi.encodeWithSelector(IVault.checkAccountStatus.selector, address(0), new address[](0));

        // Use staticcall with minimal gas to check if function exists
        // This will return false for contracts that don't implement the function
        (bool success,) = vault.staticcall{gas: 10000}(data);

        // If the call succeeds or reverts with data (function exists but validation failed),
        // the contract implements the interface
        // If it fails with no data, the function doesn't exist
        return success;
    }

    /// @notice Checks if an account is healthy for a given vault
    /// @param vault The vault address (controller vault)
    /// @param account The account address to check
    /// @return healthy True if the account is healthy
    /// @dev Calls checkAccountStatus() and expects magic value 0xb168c58f for healthy accounts
    function isAccountHealthy(
        address vault,
        address account
    ) internal view returns (bool healthy) {
        IEVC evc = IEVC(ph.getAssertionAdopter());

        // Get enabled collaterals for the account
        address[] memory collaterals = evc.getCollaterals(account);

        // Use checkAccountStatus() - all vaults implementing IVault must have this
        // The function returns magic value 0xb168c58f if healthy, or reverts if unhealthy
        try IVault(vault).checkAccountStatus(account, collaterals) returns (bytes4 magicValue) {
            // Magic value is 0xb168c58f (selector of checkAccountStatus)
            if (magicValue == IVault.checkAccountStatus.selector) {
                return true;
            }
            // If wrong magic value returned, treat as unhealthy
            return false;
        } catch {
            // If checkAccountStatus reverts, account is unhealthy
            return false;
        }
    }

    /// @notice Extracts affected accounts from vault function call data
    /// @param data The calldata for the vault function
    /// @return accounts Array of addresses that may be affected by this call
    /// @dev Parses function selectors to extract accounts:
    ///      withdraw/redeem → owner (3rd param)
    ///      transferFrom → from (1st param)
    ///      borrow → receiver (2nd param)
    ///      repay → debtor (2nd param)
    ///      liquidate → violator (1st param)
    function extractAccountsFromCalldata(
        bytes memory data
    ) internal pure returns (address[] memory accounts) {
        // Need at least 4 bytes for selector
        if (data.length < 4) {
            return new address[](0);
        }

        // Extract selector using assembly (more efficient than manual bit manipulation)
        bytes4 selector;
        assembly {
            selector := mload(add(data, 32))
        }

        // withdraw(uint256,address,address) - 0xb460af94
        // redeem(uint256,address,address) - 0xba087652
        if (selector == 0xb460af94 || selector == 0xba087652) {
            // Extract owner (3rd parameter at offset 68)
            address owner;
            assembly {
                owner := mload(add(data, 100)) // 4 + 32 + 32 + 32
            }

            accounts = new address[](1);
            accounts[0] = owner;
            return accounts;
        }

        // transferFrom(address,address,uint256) - 0x23b872dd
        if (selector == 0x23b872dd) {
            // Extract from (1st parameter at offset 4)
            address from;
            assembly {
                from := mload(add(data, 36)) // 4 + 32
            }

            accounts = new address[](1);
            accounts[0] = from;
            return accounts;
        }

        // borrow(uint256,address) - 0xc5ebeaec
        // repay(uint256,address) - 0x371fd8e6
        if (selector == 0xc5ebeaec || selector == 0x371fd8e6) {
            // Extract receiver/debtor (2nd parameter at offset 36)
            address account;
            assembly {
                account := mload(add(data, 68)) // 4 + 32 + 32
            }

            accounts = new address[](1);
            accounts[0] = account;
            return accounts;
        }

        // liquidate(address,address,uint256,uint256) - 0xc1342574
        if (selector == 0xc1342574) {
            // Extract violator (1st parameter at offset 4)
            address violator;
            assembly {
                violator := mload(add(data, 36)) // 4 + 32
            }

            accounts = new address[](1);
            accounts[0] = violator;
            return accounts;
        }

        // Function not recognized or no extractable accounts
        return new address[](0);
    }
}
