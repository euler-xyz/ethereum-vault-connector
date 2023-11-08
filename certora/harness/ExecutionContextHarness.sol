// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../../src/ExecutionContext.sol";

contract ExecutionContextHarness {
    uint public constant BATCH_DEPTH_MASK = ExecutionContext.BATCH_DEPTH_MASK;
    uint public constant ON_BEHALF_OF_ACCOUNT_MASK = ExecutionContext.ON_BEHALF_OF_ACCOUNT_MASK;
    uint public constant CHECKS_LOCK_MASK = ExecutionContext.CHECKS_LOCK_MASK;
    uint public constant IMPERSONATE_LOCK_MASK = ExecutionContext.IMPERSONATE_LOCK_MASK;
    uint public constant OPERATOR_AUTHENTICATED_MASK = ExecutionContext.OPERATOR_AUTHENTICATED_MASK;
    uint public constant PERMIT_MASK = ExecutionContext.PERMIT_MASK;
    uint public constant SIMULATION_MASK = ExecutionContext.SIMULATION_MASK;
    uint public constant STAMP_MASK = ExecutionContext.STAMP_MASK;
    uint public constant ON_BEHALF_OF_ACCOUNT_OFFSET = ExecutionContext.ON_BEHALF_OF_ACCOUNT_OFFSET;
    uint public constant STAMP_OFFSET = ExecutionContext.STAMP_OFFSET;
    uint public constant BATCH_DEPTH_INIT = ExecutionContext.BATCH_DEPTH_INIT;
    uint public constant BATCH_DEPTH_MAX = ExecutionContext.BATCH_DEPTH_MAX;
    uint public constant STAMP_DUMMY_VALUE = ExecutionContext.STAMP_DUMMY_VALUE;

    function isEqual(
        EC context1,
        EC context2
    ) external pure returns (bool result) {
        result = ExecutionContext.isEqual(context1, context2);
    }

    function getBatchDepth(EC context) external pure returns (uint8 result) {
        result = ExecutionContext.getBatchDepth(context);
    }

    function isInBatch(EC context) external pure returns (bool result) {
        result = ExecutionContext.isInBatch(context);
    }

    function isBatchDepthExceeded(
        EC context
    ) external pure returns (bool result) {
        result = ExecutionContext.isBatchDepthExceeded(context);
    }

    function setBatchDepth(
        EC context,
        uint8 batchDepth
    ) external pure returns (EC result) {
        result = ExecutionContext.setBatchDepth(context,batchDepth);
    }

    function getOnBehalfOfAccount(
        EC context
    ) external pure returns (address result) {
        result = ExecutionContext.getOnBehalfOfAccount(context);
    }

    function setOnBehalfOfAccount(
        EC context,
        address account
    ) external pure returns (EC result) {
        result = ExecutionContext.setOnBehalfOfAccount(context,account);
    }

    function areChecksInProgress(
        EC context
    ) external pure returns (bool result) {
        result = ExecutionContext.areChecksInProgress(context);
    }

    function setChecksInProgress(EC context) external pure returns (EC result) {
        result = ExecutionContext.setChecksInProgress(context);
    }

    function clearChecksInProgress(
        EC context
    ) external pure returns (EC result) {
        result = ExecutionContext.clearChecksInProgress(context);
    }

    function isImpersonationInProgress(
        EC context
    ) external pure returns (bool result) {
        result = ExecutionContext.isImpersonationInProgress(context);
    }

    function setImpersonationInProgress(
        EC context
    ) external pure returns (EC result) {
        result = ExecutionContext.setImpersonationInProgress(context);
    }

    function clearImpersonationInProgress(
        EC context
    ) external pure returns (EC result) {
        result = ExecutionContext.clearImpersonationInProgress(context);
    }

    function isOperatorAuthenticated(
        EC context
    ) external pure returns (bool result) {
        result = ExecutionContext.isOperatorAuthenticated(context);
    }

    function setOperatorAuthenticated(
        EC context
    ) external pure returns (EC result) {
        result = ExecutionContext.setOperatorAuthenticated(context);
    }

    function clearOperatorAuthenticated(
        EC context
    ) external pure returns (EC result) {
        result = ExecutionContext.clearOperatorAuthenticated(context);
    }

    function isPermitInProgress(
        EC context
    ) external pure returns (bool result) {
        result = ExecutionContext.isPermitInProgress(context);
    }

    function setPermitInProgress(EC context) external pure returns (EC result) {
        result = ExecutionContext.setPermitInProgress(context);
    }

    function clearPermitInProgress(
        EC context
    ) external pure returns (EC result) {
        result = ExecutionContext.clearPermitInProgress(context);
    }

    function isSimulationInProgress(
        EC context
    ) external pure returns (bool result) {
        result = ExecutionContext.isSimulationInProgress(context);
    }

    function setSimulationInProgress(
        EC context
    ) external pure returns (EC result) {
        result = ExecutionContext.setSimulationInProgress(context);
    }

    function clearSimulationInProgress(
        EC context
    ) external pure returns (EC result) {
        result = ExecutionContext.clearSimulationInProgress(context);
    }

    function initialize() external pure returns (EC result) {
        result = ExecutionContext.initialize();
    }
}
