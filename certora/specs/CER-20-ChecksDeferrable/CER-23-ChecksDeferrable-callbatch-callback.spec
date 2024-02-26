// CER-23: In Call and Batch, if the target is msg.sender, the caller MAY
// specify any Account address to be set in the Execution Context's on behalf of
// Account address. In that case, the authentication is not performed

methods {
    function _.authenticateCaller(address account, bool allowOperator) internal with (env e) => 
        reachedAuthCaller(e, account, allowOperator) expect (address);
}

persistent ghost bool didAuth;
function reachedAuthCaller(env e, address addr, bool allowOperator) returns address {
    // set didAuth if authenticateCaller is ever reached
    didAuth = didAuth || true;
    // this is not relevant to the rule
    // but mirrors the returned value of the summarized function
    return currentContract == e.msg.sender ? getExecutionContextOnBehalfOfAccount(e) : e.msg.sender;
}

rule call_authentication_skip {
    env e;
    address targetContract;
    address onBehalfOfAccount;
    uint256 value;
    bytes data;

    require !didAuth;
    require e.msg.sender == targetContract;
    call(e, targetContract, onBehalfOfAccount, value, data);
    assert !didAuth;
}

// TODO need similar implementation for batch