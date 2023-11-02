// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

type EC is uint;

library ExecutionContext {
    uint internal constant BATCH_DEPTH_MASK =
        0x00000000000000000000000000000000000000000000000000000000000000FF;
    uint internal constant ON_BEHALF_OF_ACCOUNT_MASK =
        0x0000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00;
    uint internal constant CHECKS_LOCK_MASK =
        0x00000000000000000000FF000000000000000000000000000000000000000000;
    uint internal constant IMPERSONATE_LOCK_MASK =
        0x000000000000000000FF00000000000000000000000000000000000000000000;
    uint internal constant OPERATOR_AUTHENTICATED_MASK =
        0x0000000000000000FF0000000000000000000000000000000000000000000000;
    uint internal constant PERMIT_MASK =
        0x00000000000000FF000000000000000000000000000000000000000000000000;
    uint internal constant SIMULATION_MASK =
        0x000000000000FF00000000000000000000000000000000000000000000000000;
    uint internal constant STAMP_MASK =
        0xFFFFFFFFFFFF0000000000000000000000000000000000000000000000000000;
    uint internal constant ON_BEHALF_OF_ACCOUNT_OFFSET = 8;
    uint internal constant STAMP_OFFSET = 208;
    uint internal constant BATCH_DEPTH_INIT = 0;
    uint internal constant BATCH_DEPTH_MAX = 9;
    uint internal constant STAMP_DUMMY_VALUE = 1;

    // None of the functions below modifies the state. All the functions operate on the copy 
    // of the execution context and return its modified value as a result. In order to update
    // one should use the result of the function call as a new execution context value.
    // i.e. the following call: executionContext.setChecksInProgress() returns the new execution
    // context value that should be written to the executionContext storage pointer:
    // executionContext = executionContext.setChecksInProgress();

    function isEqual(
        EC context1,
        EC context2
    ) internal pure returns (bool result) {
        result = EC.unwrap(context1) == EC.unwrap(context2);
    }

    function getBatchDepth(EC context) internal pure returns (uint8 result) {
        result = uint8(EC.unwrap(context) & BATCH_DEPTH_MASK);
    }

    function isInBatch(EC context) internal pure returns (bool result) {
        result = EC.unwrap(context) & BATCH_DEPTH_MASK != BATCH_DEPTH_INIT;
    }

    function isBatchDepthExceeded(
        EC context
    ) internal pure returns (bool result) {
        result = EC.unwrap(context) & BATCH_DEPTH_MASK >= BATCH_DEPTH_MAX;
    }

    /// #if_succeeds "batch depth can only change if reentrancy locks are not acquired" !areChecksInProgress(context) && !isImpersonationInProgress(context);
    function setBatchDepth(
        EC context,
        uint8 batchDepth
    ) internal pure returns (EC result) {
        result = EC.wrap((EC.unwrap(context) & ~BATCH_DEPTH_MASK) | batchDepth);
    }

    function getOnBehalfOfAccount(
        EC context
    ) internal pure returns (address result) {
        result = address(
            uint160(
                (EC.unwrap(context) & ON_BEHALF_OF_ACCOUNT_MASK) >>
                    ON_BEHALF_OF_ACCOUNT_OFFSET
            )
        );
    }

    function setOnBehalfOfAccount(
        EC context,
        address account
    ) internal pure returns (EC result) {
        result = EC.wrap(
            (EC.unwrap(context) & ~ON_BEHALF_OF_ACCOUNT_MASK) |
                (uint(uint160(account)) << ON_BEHALF_OF_ACCOUNT_OFFSET)
        );
    }

    function areChecksInProgress(
        EC context
    ) internal pure returns (bool result) {
        result = EC.unwrap(context) & CHECKS_LOCK_MASK != 0;
    }

    function setChecksInProgress(EC context) internal pure returns (EC result) {
        result = EC.wrap(EC.unwrap(context) | CHECKS_LOCK_MASK);
    }

    function clearChecksInProgress(
        EC context
    ) internal pure returns (EC result) {
        result = EC.wrap(EC.unwrap(context) & ~CHECKS_LOCK_MASK);
    }

    function isImpersonationInProgress(
        EC context
    ) internal pure returns (bool result) {
        result = EC.unwrap(context) & IMPERSONATE_LOCK_MASK != 0;
    }

    function setImpersonationInProgress(
        EC context
    ) internal pure returns (EC result) {
        result = EC.wrap(EC.unwrap(context) | IMPERSONATE_LOCK_MASK);
    }

    function clearImpersonationInProgress(
        EC context
    ) internal pure returns (EC result) {
        result = EC.wrap(EC.unwrap(context) & ~IMPERSONATE_LOCK_MASK);
    }

    function isOperatorAuthenticated(
        EC context
    ) internal pure returns (bool result) {
        result = EC.unwrap(context) & OPERATOR_AUTHENTICATED_MASK != 0;
    }

    function setOperatorAuthenticated(
        EC context
    ) internal pure returns (EC result) {
        result = EC.wrap(EC.unwrap(context) | OPERATOR_AUTHENTICATED_MASK);
    }

    function clearOperatorAuthenticated(
        EC context
    ) internal pure returns (EC result) {
        result = EC.wrap(EC.unwrap(context) & ~OPERATOR_AUTHENTICATED_MASK);
    }

    function isPermitInProgress(
        EC context
    ) internal pure returns (bool result) {
        result = EC.unwrap(context) & PERMIT_MASK != 0;
    }

    function setPermitInProgress(EC context) internal pure returns (EC result) {
        result = EC.wrap(EC.unwrap(context) | PERMIT_MASK);
    }

    function clearPermitInProgress(
        EC context
    ) internal pure returns (EC result) {
        result = EC.wrap(EC.unwrap(context) & ~PERMIT_MASK);
    }

    function isSimulationInProgress(
        EC context
    ) internal pure returns (bool result) {
        result = EC.unwrap(context) & SIMULATION_MASK != 0;
    }

    function setSimulationInProgress(
        EC context
    ) internal pure returns (EC result) {
        result = EC.wrap(EC.unwrap(context) | SIMULATION_MASK);
    }

    function clearSimulationInProgress(
        EC context
    ) internal pure returns (EC result) {
        result = EC.wrap(EC.unwrap(context) & ~SIMULATION_MASK);
    }

    function initialize() internal pure returns (EC result) {
        // prepopulate the execution context storage slot to optimize gas consumption
        // (it should never be cleared again thanks to the stamp)
        result = EC.wrap(STAMP_DUMMY_VALUE << STAMP_OFFSET);
    }
}
