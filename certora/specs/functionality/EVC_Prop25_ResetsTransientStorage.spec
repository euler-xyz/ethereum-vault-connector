/**
 * Verification of:
 *   All the storage variables declared in the TransientStorage contract must return to the default value after the top-level EVC call.
 **/

import "../utils/IsMustRevertFunction.spec";

methods {
    function getRawExecutionContext() external returns (uint256) envfree;
    function getExecutionContextDefault() external returns (uint256) envfree;
    // function getExecutionContextCallDepth() external returns (uint8) envfree;
    function areAccountStatusChecksEmpty() external returns (bool) envfree;
    function areVaultStatusChecksEmpty() external returns (bool) envfree;
    function getCurrentOnBehalfOfAccount(address) external returns (address,bool) envfree;
}

/**
 * Verify that after any function call of call depth zero, both account and
 * vault status checks are empty, and the execution context is set back to its
 * default value.
 * We ignore must-revert functions to avoid sanity issues. Additionally, we
 * ignore getCurrentOnBehalfOfAccount() as it always revers on call depth zero.
 */
invariant topLevelFunctionDontChangeTransientStorage()
    // getExecutionContextCallDepth() == 0 &&
    areAccountStatusChecksEmpty() && areVaultStatusChecksEmpty() &&
    getRawExecutionContext() == getExecutionContextDefault()
    filtered { f ->
        !isMustRevertFunction(f) &&
        f.selector != sig:getCurrentOnBehalfOfAccount(address).selector
    }

/**
 * Check that `getCurrentOnBehalfOfAccount` always reverts in case the invariant holds.
 * This justifies the filter applied to the invariant above. 
 */
rule getCurrentOnBehalfOfAccountAlwaysReverts() {
    requireInvariant topLevelFunctionDontChangeTransientStorage();
    env e;
    address controllerToCheck;
    getCurrentOnBehalfOfAccount@withrevert(controllerToCheck);
    assert(lastReverted);
}