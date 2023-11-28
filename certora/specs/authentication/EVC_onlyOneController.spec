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
