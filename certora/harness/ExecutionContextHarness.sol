// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../../src/ExecutionContext.sol";

contract ExecutionContextHarness {
    // uint public constant CALL_DEPTH_MASK = ExecutionContext.CALL_DEPTH_MASK;
    uint public constant ON_BEHALF_OF_ACCOUNT_MASK = ExecutionContext.ON_BEHALF_OF_ACCOUNT_MASK;
    uint public constant CHECKS_LOCK_MASK = ExecutionContext.CHECKS_LOCK_MASK;
    uint public constant IMPERSONATE_LOCK_MASK = ExecutionContext.IMPERSONATE_LOCK_MASK;
    uint public constant OPERATOR_AUTHENTICATED_MASK = ExecutionContext.OPERATOR_AUTHENTICATED_MASK;
    uint public constant SIMULATION_MASK = ExecutionContext.SIMULATION_MASK;
    uint public constant STAMP_MASK = ExecutionContext.STAMP_MASK;
    uint public constant ON_BEHALF_OF_ACCOUNT_OFFSET = ExecutionContext.ON_BEHALF_OF_ACCOUNT_OFFSET;
    uint public constant STAMP_OFFSET = ExecutionContext.STAMP_OFFSET;
    // uint public constant CALL_DEPTH_MAX = ExecutionContext.CALL_DEPTH_MAX;
    uint public constant STAMP_DUMMY_VALUE = ExecutionContext.STAMP_DUMMY_VALUE;

    function areChecksDeferred(EC context) external pure returns (bool result) {
        result = ExecutionContext.areChecksDeferred(context);
    }

    // Call Depth appears to be depricated
    // function getCallDepth(EC context) external pure returns (uint8 result) {
    //     result = ExecutionContext.getCallDepth(context);
    // }

    function increaseCallDepth(EC context) external pure returns (EC result) {
        result = ExecutionContext.increaseCallDepth(context);
    }

    function getOnBehalfOfAccount(EC context) external pure returns (address result) {
        result = ExecutionContext.getOnBehalfOfAccount(context);
    }

    function setOnBehalfOfAccount(EC context, address account) external pure returns (EC result) {
        result = ExecutionContext.setOnBehalfOfAccount(context,account);
    }

    function areChecksInProgress(EC context) external pure returns (bool result) {
        result = ExecutionContext.areChecksInProgress(context);
    }

    function setChecksInProgress(EC context) external pure returns (EC result) {
        result = ExecutionContext.setChecksInProgress(context);
    }

    function isImpersonationInProgress(EC context) external pure returns (bool result) {
        result = ExecutionContext.isImpersonationInProgress(context);
    }

    function setImpersonationInProgress(EC context) external pure returns (EC result) {
        result = ExecutionContext.setImpersonationInProgress(context);
    }

    function isOperatorAuthenticated(EC context) external pure returns (bool result) {
        result = ExecutionContext.isOperatorAuthenticated(context);
    }

    function setOperatorAuthenticated(EC context) external pure returns (EC result) {
        result = ExecutionContext.setOperatorAuthenticated(context);
    }

    function clearOperatorAuthenticated(EC context) external pure returns (EC result) {
        result = ExecutionContext.clearOperatorAuthenticated(context);
    }

    function isSimulationInProgress(EC context) external pure returns (bool result) {
        result = ExecutionContext.isSimulationInProgress(context);
    }

    function setSimulationInProgress(EC context) external pure returns (EC result) {
        result = ExecutionContext.setSimulationInProgress(context);
    }

    function initialize() external pure returns (EC result) {
        result = ExecutionContext.initialize();
    }
}
