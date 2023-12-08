/**
 * Verification of:
 *   Each external call, that the EVC performs, restores the value of the
 *   execution context so that it’s equal to the value just before the external
 *   call was performed.
 **/

import "../utils/IsMustRevertFunction.spec";
import "../utils/CallOpSanity.spec";

methods {
    function getRawExecutionContext() external returns (uint256) envfree;
}

/**
 * Verify that any functions restores the execution context to whatever it was
 * beforehand.
 */
rule noFunctionChangesExecutionContext(method f) filtered {f -> !isMustRevertFunction(f)} 
{
    env e;
    calldataarg args;

    uint256 preEC = getRawExecutionContext();
    f(e, args);
    assert(preEC == getRawExecutionContext());
}