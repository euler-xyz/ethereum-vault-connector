methods {
    function CALL_DEPTH_MASK() external returns (uint) envfree;
    function ON_BEHALF_OF_ACCOUNT_MASK() external returns (uint) envfree;
    function CHECKS_LOCK_MASK() external returns (uint) envfree;
    function IMPERSONATE_LOCK_MASK() external returns (uint) envfree;
    function OPERATOR_AUTHENTICATED_MASK() external returns (uint) envfree;
    function SIMULATION_MASK() external returns (uint) envfree;
    function STAMP_MASK() external returns (uint) envfree;
    function ON_BEHALF_OF_ACCOUNT_OFFSET() external returns (uint) envfree;
    function STAMP_OFFSET() external returns (uint) envfree;
    function CALL_DEPTH_MAX() external returns (uint) envfree;
    function STAMP_DUMMY_VALUE() external returns (uint) envfree;

    function areChecksDeferred(ExecutionContextHarness.EC context) external returns (bool) envfree;
    // getCallDepth appears depricated
    // function getCallDepth(ExecutionContextHarness.EC context) external returns (uint8) envfree;
    function increaseCallDepth(ExecutionContextHarness.EC context) external returns (ExecutionContextHarness.EC) envfree;
    function getOnBehalfOfAccount(ExecutionContextHarness.EC context) external returns (address) envfree;
    function setOnBehalfOfAccount(ExecutionContextHarness.EC context, address account) external returns (ExecutionContextHarness.EC) envfree;
    function areChecksInProgress(ExecutionContextHarness.EC context) external returns (bool) envfree;
    function setChecksInProgress(ExecutionContextHarness.EC context) external returns (ExecutionContextHarness.EC) envfree;
    function isImpersonationInProgress(ExecutionContextHarness.EC context) external returns (bool) envfree;
    function setImpersonationInProgress(ExecutionContextHarness.EC context) external returns (ExecutionContextHarness.EC) envfree;
    function isOperatorAuthenticated(ExecutionContextHarness.EC context) external returns (bool) envfree;
    function setOperatorAuthenticated(ExecutionContextHarness.EC context) external returns (ExecutionContextHarness.EC) envfree;
    function clearOperatorAuthenticated(ExecutionContextHarness.EC context) external returns (ExecutionContextHarness.EC) envfree;
    function isSimulationInProgress(ExecutionContextHarness.EC context) external returns (bool) envfree;
    function setSimulationInProgress(ExecutionContextHarness.EC context) external returns (ExecutionContextHarness.EC) envfree;
    function initialize() external returns (ExecutionContextHarness.EC) envfree;
}

/// check that bitmasks are pairwise disjoint
rule check_bitmasks_disjoint() {
    assert(CALL_DEPTH_MASK() & ON_BEHALF_OF_ACCOUNT_MASK() == 0);
    assert(CALL_DEPTH_MASK() & CHECKS_LOCK_MASK() == 0);
    assert(CALL_DEPTH_MASK() & IMPERSONATE_LOCK_MASK() == 0);
    assert(CALL_DEPTH_MASK() & OPERATOR_AUTHENTICATED_MASK() == 0);
    assert(CALL_DEPTH_MASK() & SIMULATION_MASK() == 0);
    assert(CALL_DEPTH_MASK() & STAMP_MASK() == 0);

    assert(ON_BEHALF_OF_ACCOUNT_MASK() & CHECKS_LOCK_MASK() == 0);
    assert(ON_BEHALF_OF_ACCOUNT_MASK() & IMPERSONATE_LOCK_MASK() == 0);
    assert(ON_BEHALF_OF_ACCOUNT_MASK() & OPERATOR_AUTHENTICATED_MASK() == 0);
    assert(ON_BEHALF_OF_ACCOUNT_MASK() & SIMULATION_MASK() == 0);
    assert(ON_BEHALF_OF_ACCOUNT_MASK() & STAMP_MASK() == 0);

    assert(CHECKS_LOCK_MASK() & IMPERSONATE_LOCK_MASK() == 0);
    assert(CHECKS_LOCK_MASK() & OPERATOR_AUTHENTICATED_MASK() == 0);
    assert(CHECKS_LOCK_MASK() & SIMULATION_MASK() == 0);
    assert(CHECKS_LOCK_MASK() & STAMP_MASK() == 0);

    assert(IMPERSONATE_LOCK_MASK() & OPERATOR_AUTHENTICATED_MASK() == 0);
    assert(IMPERSONATE_LOCK_MASK() & SIMULATION_MASK() == 0);
    assert(IMPERSONATE_LOCK_MASK() & STAMP_MASK() == 0);

    assert(OPERATOR_AUTHENTICATED_MASK() & SIMULATION_MASK() == 0);
    assert(OPERATOR_AUTHENTICATED_MASK() & STAMP_MASK() == 0);

    assert(SIMULATION_MASK() & STAMP_MASK() == 0);
}

/// check that the bitmasks cover all the bits
rule check_bitmasks_coverall() {
    assert(
        CALL_DEPTH_MASK() |
        ON_BEHALF_OF_ACCOUNT_MASK() |
        CHECKS_LOCK_MASK() |
        IMPERSONATE_LOCK_MASK() |
        OPERATOR_AUTHENTICATED_MASK() |
        SIMULATION_MASK() |
        STAMP_MASK() == ~require_uint256(0)
    );
}

/// check that the offsets are right
rule check_bitmasks_offsets() {
    assert(CALL_DEPTH_MASK() <= (1 << ON_BEHALF_OF_ACCOUNT_OFFSET()));
    assert(ON_BEHALF_OF_ACCOUNT_MASK() & require_uint256((1 << ON_BEHALF_OF_ACCOUNT_OFFSET()) - 1) == 0);
    assert(STAMP_MASK() & require_uint256((1 << STAMP_OFFSET()) - 1) == 0);
}

// Call Depth appears depricated
// /// check basic functionality of getCallDepth and increaseCallDepth
// rule check_call_depth(uint ec) {
//     uint8 before = getCallDepth(ec);
//     uint newec = increaseCallDepth(ec);
//     assert(to_mathint(getCallDepth(newec)) == before + 1);
// }
// 
// rule check_call_depth_maximum(uint ec) {
//     uint8 newCallDepth = require_uint8(getCallDepth(ec) + 2);
//     // TODO: CALL_DEPTH_MAX suggests that the value itself is still valid. It is not.
//     require(require_uint256(newCallDepth) < CALL_DEPTH_MAX());
//     uint ec2 = increaseCallDepth(ec);
//     uint ec3 = increaseCallDepth(ec2);
//     assert(newCallDepth == getCallDepth(ec3));
// }

/// check basic functionality of getOnBehalfOfAccount and setOnBehalfOfAccount
rule check_on_behalf_of_account(uint ec, address adr) {
    address before = getOnBehalfOfAccount(ec);
    uint newec = setOnBehalfOfAccount(ec, adr);
    assert(getOnBehalfOfAccount(newec) == adr);
    uint resetec = setOnBehalfOfAccount(ec, before);
    assert(resetec == ec);
}
