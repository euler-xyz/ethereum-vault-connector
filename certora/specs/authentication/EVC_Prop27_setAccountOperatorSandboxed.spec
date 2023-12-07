
/**
 * EVC Spec #27
 * Calling setAccountOperator does not affect the state for any operator
 * other than the target of the function call.
 * Verification report: https://prover.certora.com/output/65266/f5679749c8e44f979cb48ef89dfef608?anonymousKey=3303ccb55f2b00608cbb86b73eb90623113a5014
 */
methods {
    function getOperator(uint152, address) external returns (uint256) envfree;
    function getAddressPrefix(address) external returns (uint152) envfree;
}

rule setAccountOperatorSandboxed(address account, address operator, bool authorized) {
    address otherAccount;
    address otherOperator;
    env e;

    uint152 addressPrefix = getAddressPrefix(otherAccount);
    // either otherAccount is from another prefix, or the operator is different
    require(getAddressPrefix(account) != addressPrefix || operator != otherOperator);

    uint256 operatorBefore = getOperator(addressPrefix, otherOperator);
    setAccountOperator(e, account, operator, authorized);
    uint256 operatorAfter = getOperator(addressPrefix, otherOperator);

    // the bitmask for a different account or different operator was not changed
    assert(operatorBefore == operatorAfter);
}