// CER-23: In Call and Batch, if the target is msg.sender, the caller MAY
// specify any Account address to be set in the Execution Context's on behalf of
// Account address. In that case, the authentication is not performed

methods {
    function EthereumVaultConnector.authenticateCaller(address account, bool allowOperator, bool checkLockdownMode) internal returns (address) with (env e) => 
        reachedAuthCaller(e, account, allowOperator);
}

persistent ghost bool didAuth;
function reachedAuthCaller(env e, address addr, bool allowOperator) returns address {
    // set didAuth if authenticateCaller is ever reached
    didAuth = true;
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

    require e.msg.sender == targetContract;
    require !didAuth;
    call(e, targetContract, onBehalfOfAccount, value, data);
    assert !didAuth;
}

rule batch_authentication_skip {
    env e;
    IEVC.BatchItem[] items;
    require items.length == 1;
    require e.msg.sender == items[0].targetContract;
    require !didAuth;
    batch(e, items);
    assert !didAuth;
}
