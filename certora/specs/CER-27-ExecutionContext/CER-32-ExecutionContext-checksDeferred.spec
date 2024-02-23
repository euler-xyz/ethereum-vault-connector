// CER-32: Execution Context MUST keep track of whether the Checks are deferred
// with a boolean flag. The flag MUST be set  when a Checks-deferrable Call
// starts and MUST be cleared at the end of it, but only when the flag was not
// set before the call.

methods {
    function areChecksDeferred() external returns (bool) envfree;
}

// persistent ghost bool checksDeferredGhost;


// Assume the initial value of contextCache.areChecksDeferred() is false
// (Should dig into whether or not this is a valid assumption. This does
// not seem to explicitly be initialized by a constructor but perhaps this
// is still how it works because of how uninitialized variables work in 
// solidity)

function restoreChecksDeferred_call {
    env e;
    address targetContract;
    address onBehalfOfAccount;
    uint256 value;
    bytes data;

    require !areChecksDeferred();
    call(e, targetContract, onBehalfOfAccount, value, data);
    assert !areChecksDeferred();
}