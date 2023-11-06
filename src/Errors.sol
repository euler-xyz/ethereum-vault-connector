// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "./interfaces/ICreditVaultConnector.sol";

contract Errors {
    error CVC_NotAuthorized();
    error CVC_AccountOwnerNotRegistered();
    error CVC_OnBehalfOfAccountNotAuthenticated();
    error CVC_InvalidOperatorStatus();
    error CVC_InvalidNonce();
    error CVC_InvalidAddress();
    error CVC_InvalidTimestamp();
    error CVC_InvalidValue();
    error CVC_InvalidData();
    error CVC_ChecksReentrancy();
    error CVC_ImpersonateReentrancy();
    error CVC_ControllerViolation();
    error CVC_SimulationBatchNested();
    error CVC_RevertedBatchResult(
        ICVC.BatchItemResult[] batchItemsResult,
        ICVC.BatchItemResult[] accountsStatusResult,
        ICVC.BatchItemResult[] vaultsStatusResult
    );
    error CVC_BatchPanic();
    error CVC_EmptyError();
}
