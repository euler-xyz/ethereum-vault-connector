/**

Verification of: 
Each Account can have at most one Controller Vault enabled at a time unless it's a transient state during a Checks-deferrable Call. This is how single-liability-per-account is enforced.

Verification results: https://prover.certora.com/output/40726/5592f88067aa4582899f709c8dd0a17d/?anonymousKey=ce7f5f97dbcb3bd8962ba7d79ba4513204d3608d

Mutations: https://mutation-testing.certora.com/?id=df26ec00-d98e-469e-9819-3beaeeae1f0a&anonymousKey=f8204e4e-b148-4a67-a3d1-078d2fdbf921 
to run mutations: 
certoraMutate --prover_conf certora/conf/authentication/EVC_onlyOneController.conf --mutation_conf certora/conf/authentication/mutateProp2.conf


**/

methods {
    function numOfController(address account) external returns(uint8) envfree;
    function getCurrentCallDepth() external returns(uint256) envfree;
}

// Helper method: the call depth is always zero (while no method is running)
invariant callDepthIsZero() getCurrentCallDepth() == 0;

/**
 * Check that we never have more than one controller.
 *
 * It does not work for batch(): this relies on batch() calling
 * checkAccountStatusInternal for all accounts whose controllers might have
 * changed.
 */
invariant onlyOneController(address a)
    numOfController(a) <= 1
    filtered { // TODO: make this work for batch as well
        f -> f.selector != sig:batch(IEVC.BatchItem[] calldata).selector
    }
    { preserved { requireInvariant callDepthIsZero(); } }
