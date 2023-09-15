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
    uint internal constant STAMP_MASK =
        0xFFFFFFFFFFFFFFFFFF0000000000000000000000000000000000000000000000;
    uint internal constant ON_BEHALF_OF_ACCOUNT_OFFSET = 8;
    uint internal constant STAMP_OFFSET = 184;
    uint internal constant BATCH_DEPTH_INIT = 0;
    uint internal constant BATCH_DEPTH_MAX = 9;
    uint internal constant STAMP_DUMMY_VALUE = 1;

    function isInBatch(EC context) internal pure returns (bool result) {
        result = EC.unwrap(context) & BATCH_DEPTH_MASK != BATCH_DEPTH_INIT;
    }

    function isBatchDepthExceeded(
        EC context
    ) internal pure returns (bool result) {
        result = EC.unwrap(context) & BATCH_DEPTH_MASK >= BATCH_DEPTH_MAX;
    }

    /// #if_succeeds "batch depth can only change if reentrancy locks are not acquired" !areChecksInProgress(context) && !isImpersonationInProgress(context);
    function increaseBathDepth(EC context) internal pure returns (EC result) {
        unchecked {
            result = EC.wrap(EC.unwrap(context) + 1);
        }
    }

    /// #if_succeeds "batch depth can only change if reentrancy locks are not acquired" !areChecksInProgress(context) && !isImpersonationInProgress(context);
    function decreaseBathDepth(EC context) internal pure returns (EC result) {
        unchecked {
            result = EC.wrap(EC.unwrap(context) - 1);
        }
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

    /// #if_succeeds "check lock can only change if impersonate lock is not acquired" !isImpersonationInProgress(context);
    function setChecksInProgress(EC context) internal pure returns (EC result) {
        result = EC.wrap(EC.unwrap(context) | CHECKS_LOCK_MASK);
    }

    /// #if_succeeds "check lock can only change if impersonate lock is not acquired" !isImpersonationInProgress(context);
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

    function initialize() internal pure returns (EC result) {
        // prepopulate the execution context storage slot to optimize gas consumption
        // (it should never be cleared again thanks to the stamp)
        result = EC.wrap(STAMP_DUMMY_VALUE << STAMP_OFFSET);
    }
}
