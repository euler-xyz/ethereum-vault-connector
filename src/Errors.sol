// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.19;

import "./interfaces/IEthereumVaultConnector.sol";

/// @title Errors
/// @author Euler Labs (https://www.eulerlabs.com/)
/// @notice This contract implements the error messages for the Ethereum Vault Connector.
contract Errors {
    error EVC_NotAuthorized();
    error EVC_AccountOwnerNotRegistered();
    error EVC_OnBehalfOfAccountNotAuthenticated();
    error EVC_InvalidOperatorStatus();
    error EVC_InvalidNonce();
    error EVC_InvalidAddress();
    error EVC_InvalidTimestamp();
    error EVC_InvalidValue();
    error EVC_InvalidData();
    error EVC_ChecksReentrancy();
    error EVC_ImpersonateReentrancy();
    error EVC_ControllerViolation();
    error EVC_SimulationBatchNested();
    error EVC_RevertedBatchResult(
        IEVC.BatchItemResult[] batchItemsResult,
        IEVC.StatusCheckResult[] accountsStatusResult,
        IEVC.StatusCheckResult[] vaultsStatusResult
    );
    error EVC_BatchPanic();
    error EVC_EmptyError();
}
