methods {
    function BATCH_DEPTH_MASK() external returns (uint) envfree;
    function ON_BEHALF_OF_ACCOUNT_MASK() external returns (uint) envfree;
    function CHECKS_LOCK_MASK() external returns (uint) envfree;
    function IMPERSONATE_LOCK_MASK() external returns (uint) envfree;
    function OPERATOR_AUTHENTICATED_MASK() external returns (uint) envfree;
    function PERMIT_MASK() external returns (uint) envfree;
    function SIMULATION_MASK() external returns (uint) envfree;
    function STAMP_MASK() external returns (uint) envfree;
    function ON_BEHALF_OF_ACCOUNT_OFFSET() external returns (uint) envfree;
    function STAMP_OFFSET() external returns (uint) envfree;
    function BATCH_DEPTH_INIT() external returns (uint) envfree;
    function BATCH_DEPTH_MAX() external returns (uint) envfree;
    function STAMP_DUMMY_VALUE() external returns (uint) envfree;

    function isEqual(
        ExecutionContextHarness.EC context1,
        ExecutionContextHarness.EC context2
    ) external returns (bool) envfree;

    function getBatchDepth(ExecutionContextHarness.EC context) external returns (uint8) envfree;

    function isInBatch(ExecutionContextHarness.EC context) external returns (bool) envfree;

    function isBatchDepthExceeded(
        ExecutionContextHarness.EC context
    ) external returns (bool) envfree;

    function setBatchDepth(
        ExecutionContextHarness.EC context,
        uint8 batchDepth
    ) external returns (ExecutionContextHarness.EC) envfree;

    function getOnBehalfOfAccount(
        ExecutionContextHarness.EC context
    ) external returns (address) envfree;

    function setOnBehalfOfAccount(
        ExecutionContextHarness.EC context,
        address account
    ) external returns (ExecutionContextHarness.EC) envfree;

    function areChecksInProgress(
        ExecutionContextHarness.EC context
    ) external returns (bool) envfree;

    function setChecksInProgress(ExecutionContextHarness.EC context) external returns (ExecutionContextHarness.EC) envfree;

    function clearChecksInProgress(
        ExecutionContextHarness.EC context
    ) external returns (ExecutionContextHarness.EC) envfree;

    function isImpersonationInProgress(
        ExecutionContextHarness.EC context
    ) external returns (bool) envfree;

    function setImpersonationInProgress(
        ExecutionContextHarness.EC context
    ) external returns (ExecutionContextHarness.EC) envfree;

    function clearImpersonationInProgress(
        ExecutionContextHarness.EC context
    ) external returns (ExecutionContextHarness.EC) envfree;

    function isOperatorAuthenticated(
        ExecutionContextHarness.EC context
    ) external returns (bool) envfree;

    function setOperatorAuthenticated(
        ExecutionContextHarness.EC context
    ) external returns (ExecutionContextHarness.EC) envfree;

    function clearOperatorAuthenticated(
        ExecutionContextHarness.EC context
    ) external returns (ExecutionContextHarness.EC) envfree;

    function isPermitInProgress(
        ExecutionContextHarness.EC context
    ) external returns (bool) envfree;

    function setPermitInProgress(ExecutionContextHarness.EC context) external returns (ExecutionContextHarness.EC) envfree;

    function clearPermitInProgress(
        ExecutionContextHarness.EC context
    ) external returns (ExecutionContextHarness.EC) envfree;

    function isSimulationInProgress(
        ExecutionContextHarness.EC context
    ) external returns (bool) envfree;

    function setSimulationInProgress(
        ExecutionContextHarness.EC context
    ) external returns (ExecutionContextHarness.EC) envfree;

    function clearSimulationInProgress(
        ExecutionContextHarness.EC context
    ) external returns (ExecutionContextHarness.EC) envfree;

    function initialize() external returns (ExecutionContextHarness.EC) envfree;
}

//rule sanity(method f) {
//    env e;
//    calldataarg args;
//    f(e, args);
//    assert(false);
//}

/// check that bitmasks are pairwise disjoint
rule check_bitmasks_disjoint() {
    assert(BATCH_DEPTH_MASK() & ON_BEHALF_OF_ACCOUNT_MASK() == 0);
    assert(BATCH_DEPTH_MASK() & CHECKS_LOCK_MASK() == 0);
    assert(BATCH_DEPTH_MASK() & IMPERSONATE_LOCK_MASK() == 0);
    assert(BATCH_DEPTH_MASK() & OPERATOR_AUTHENTICATED_MASK() == 0);
    assert(BATCH_DEPTH_MASK() & PERMIT_MASK() == 0);
    assert(BATCH_DEPTH_MASK() & SIMULATION_MASK() == 0);
    assert(BATCH_DEPTH_MASK() & STAMP_MASK() == 0);

    assert(ON_BEHALF_OF_ACCOUNT_MASK() & CHECKS_LOCK_MASK() == 0);
    assert(ON_BEHALF_OF_ACCOUNT_MASK() & IMPERSONATE_LOCK_MASK() == 0);
    assert(ON_BEHALF_OF_ACCOUNT_MASK() & OPERATOR_AUTHENTICATED_MASK() == 0);
    assert(ON_BEHALF_OF_ACCOUNT_MASK() & PERMIT_MASK() == 0);
    assert(ON_BEHALF_OF_ACCOUNT_MASK() & SIMULATION_MASK() == 0);
    assert(ON_BEHALF_OF_ACCOUNT_MASK() & STAMP_MASK() == 0);

    assert(CHECKS_LOCK_MASK() & IMPERSONATE_LOCK_MASK() == 0);
    assert(CHECKS_LOCK_MASK() & OPERATOR_AUTHENTICATED_MASK() == 0);
    assert(CHECKS_LOCK_MASK() & PERMIT_MASK() == 0);
    assert(CHECKS_LOCK_MASK() & SIMULATION_MASK() == 0);
    assert(CHECKS_LOCK_MASK() & STAMP_MASK() == 0);

    assert(IMPERSONATE_LOCK_MASK() & OPERATOR_AUTHENTICATED_MASK() == 0);
    assert(IMPERSONATE_LOCK_MASK() & PERMIT_MASK() == 0);
    assert(IMPERSONATE_LOCK_MASK() & SIMULATION_MASK() == 0);
    assert(IMPERSONATE_LOCK_MASK() & STAMP_MASK() == 0);

    assert(OPERATOR_AUTHENTICATED_MASK() & PERMIT_MASK() == 0);
    assert(OPERATOR_AUTHENTICATED_MASK() & SIMULATION_MASK() == 0);
    assert(OPERATOR_AUTHENTICATED_MASK() & STAMP_MASK() == 0);

    assert(PERMIT_MASK() & SIMULATION_MASK() == 0);
    assert(PERMIT_MASK() & STAMP_MASK() == 0);

    assert(SIMULATION_MASK() & STAMP_MASK() == 0);
}

/// check that the bitmasks cover all the bits
rule check_bitmasks_coverall() {
    assert(
        BATCH_DEPTH_MASK() |
        ON_BEHALF_OF_ACCOUNT_MASK() |
        CHECKS_LOCK_MASK() |
        IMPERSONATE_LOCK_MASK() |
        OPERATOR_AUTHENTICATED_MASK() |
        PERMIT_MASK() |
        SIMULATION_MASK() |
        STAMP_MASK() == ~require_uint256(0)
    );
}

/// check that the offsets are right
rule check_bitmasks_offsets() {
    assert(BATCH_DEPTH_MASK() <= (1 << ON_BEHALF_OF_ACCOUNT_OFFSET()));
    assert(ON_BEHALF_OF_ACCOUNT_MASK() & require_uint256((1 << ON_BEHALF_OF_ACCOUNT_OFFSET()) - 1) == 0);
    assert(STAMP_MASK() & require_uint256((1 << STAMP_OFFSET()) - 1) == 0);
}

/// check that batch depth zero means we are not in a batch
invariant check_batch_zero_is_not_in_batch(uint ec)
    getBatchDepth(ec) != 0 <=> isInBatch(ec);