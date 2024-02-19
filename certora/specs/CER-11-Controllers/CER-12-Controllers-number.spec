/**

Verification of: 
Each Account can have at most one Controller Vault enabled at a time unless it's a transient state during a Checks-deferrable Call. This is how single-liability-per-account is enforced.

**/

methods {
    function numOfController(address account) external returns(uint8) envfree;
}

/**
 * Check that we never have more than one controller.
 *
 * It does not work for batch(), as it requires rather complex reasoning. Some
 * pieces necessary for this reasoning:
 * - the account status checks verifies that there is only a single controller.
 * - the only place that adds a controller issues an account status check for
 *   the respective account, either immediately or by registering it to the set.
 * - at the end of batch(), the execution context is restored.
 */
invariant onlyOneController(address a)
    numOfController(a) <= 1
    filtered { // TODO: make this work for batch as well
        f -> f.selector != sig:batch(IEVC.BatchItem[] calldata).selector
    }
