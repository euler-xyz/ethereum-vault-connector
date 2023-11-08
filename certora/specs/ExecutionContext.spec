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
}

//rule sanity(method f) {
//    env e;
//    calldataarg args;
//    f(e, args);
//    assert(false);
//}

rule check_bitmasks_disjoint() {
    // check that bitmasks are pairwise disjoint
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

rule check_bitmasks_coverall() {
    // check that the bitmasks cover all the bits
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