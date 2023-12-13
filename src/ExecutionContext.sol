// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.19;

type EC is uint256;

/// @title ExecutionContext
/// @author Euler Labs (https://www.eulerlabs.com/)
/// @notice This library provides functions for managing the execution context in the Ethereum Vault Connector.
/// @dev The execution context is a bit field that stores the following information:
/// @dev - call depth - used to indicate the number of nested checks-deferrable calls
/// @dev - on behalf of account - an account on behalf of which the currently executed operation is being performed
/// @dev - checks lock flag - used to indicate that the account/vault status checks are in progress. This flag is used
/// to prevent re-entrancy.
/// @dev - impersonation lock flag - used to indicate that the currently executed operation is impersonating an account.
/// This flag is used to prevent re-entrancy.
/// @dev - operator authenticated flag - used to indicate that the currently executed operation is being performed by
/// the account operator
/// @dev - simulation flag - used to indicate that the currently executed batch call is a simulation
/// @dev - stamp - dummy value for optimization purposes
library ExecutionContext {
    uint256 internal constant CALL_DEPTH_MASK = 0x00000000000000000000000000000000000000000000000000000000000000FF;
    uint256 internal constant ON_BEHALF_OF_ACCOUNT_MASK =
        0x0000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00;
    uint256 internal constant CHECKS_LOCK_MASK = 0x00000000000000000000FF000000000000000000000000000000000000000000;
    uint256 internal constant IMPERSONATE_LOCK_MASK = 0x000000000000000000FF00000000000000000000000000000000000000000000;
    uint256 internal constant OPERATOR_AUTHENTICATED_MASK =
        0x0000000000000000FF0000000000000000000000000000000000000000000000;
    uint256 internal constant SIMULATION_MASK = 0x00000000000000FF000000000000000000000000000000000000000000000000;
    uint256 internal constant STAMP_MASK = 0xFFFFFFFFFFFFFF00000000000000000000000000000000000000000000000000;
    uint256 internal constant ON_BEHALF_OF_ACCOUNT_OFFSET = 8;
    uint256 internal constant STAMP_OFFSET = 200;
    uint256 internal constant CALL_DEPTH_MAX = 10; // must not exceed 255
    uint256 internal constant STAMP_DUMMY_VALUE = 1;

    error CallDepthViolation();

    // None of the functions below modifies the state. All the functions operate on the copy
    // of the execution context and return its modified value as a result. In order to update
    // one should use the result of the function call as a new execution context value.
    // i.e. the following call: executionContext.setChecksInProgress() returns the new execution
    // context value that should be written to the executionContext storage pointer:
    // executionContext = executionContext.setChecksInProgress();

    function areChecksDeferred(EC context) internal pure returns (bool result) {
        result = EC.unwrap(context) & CALL_DEPTH_MASK != 0;
    }

    function getCallDepth(EC context) internal pure returns (uint8 result) {
        result = uint8(EC.unwrap(context) & CALL_DEPTH_MASK);
    }

    function increaseCallDepth(EC context) internal pure returns (EC result) {
        if (getCallDepth(context) > CALL_DEPTH_MAX - 1) {
            revert CallDepthViolation();
        }

        unchecked {
            result = EC.wrap(EC.unwrap(context) + 1);
        }
    }

    function getOnBehalfOfAccount(EC context) internal pure returns (address result) {
        result = address(uint160((EC.unwrap(context) & ON_BEHALF_OF_ACCOUNT_MASK) >> ON_BEHALF_OF_ACCOUNT_OFFSET));
    }

    function setOnBehalfOfAccount(EC context, address account) internal pure returns (EC result) {
        result = EC.wrap(
            (EC.unwrap(context) & ~ON_BEHALF_OF_ACCOUNT_MASK)
                | (uint256(uint160(account)) << ON_BEHALF_OF_ACCOUNT_OFFSET)
        );
    }

    function areChecksInProgress(EC context) internal pure returns (bool result) {
        result = EC.unwrap(context) & CHECKS_LOCK_MASK != 0;
    }

    function setChecksInProgress(EC context) internal pure returns (EC result) {
        result = EC.wrap(EC.unwrap(context) | CHECKS_LOCK_MASK);
    }

    function isImpersonationInProgress(EC context) internal pure returns (bool result) {
        result = EC.unwrap(context) & IMPERSONATE_LOCK_MASK != 0;
    }

    function setImpersonationInProgress(EC context) internal pure returns (EC result) {
        result = EC.wrap(EC.unwrap(context) | IMPERSONATE_LOCK_MASK);
    }

    function isOperatorAuthenticated(EC context) internal pure returns (bool result) {
        result = EC.unwrap(context) & OPERATOR_AUTHENTICATED_MASK != 0;
    }

    function setOperatorAuthenticated(EC context) internal pure returns (EC result) {
        result = EC.wrap(EC.unwrap(context) | OPERATOR_AUTHENTICATED_MASK);
    }

    function clearOperatorAuthenticated(EC context) internal pure returns (EC result) {
        result = EC.wrap(EC.unwrap(context) & ~OPERATOR_AUTHENTICATED_MASK);
    }

    function isSimulationInProgress(EC context) internal pure returns (bool result) {
        result = EC.unwrap(context) & SIMULATION_MASK != 0;
    }

    function setSimulationInProgress(EC context) internal pure returns (EC result) {
        result = EC.wrap(EC.unwrap(context) | SIMULATION_MASK);
    }

    function initialize() internal pure returns (EC result) {
        // prepopulate the execution context storage slot to optimize gas consumption
        // (it should never be cleared again thanks to the stamp)
        result = EC.wrap(STAMP_DUMMY_VALUE << STAMP_OFFSET);
    }
}
