// CER-23: In Call and Batch, if the target is msg.sender, the caller MAY
// specify any Account address to be set in the Execution Context's on behalf of
// Account address. In that case, the authentication is not performed


rule call_authentication_skip {
    env e;
    address targetContract;
    address onBehalfOfAccount1;
    address onBehalfOfAccount2;
    uint256 value;
    bytes data;

    // We assume e.msg.sender == targetContract
    // and compare between two executions with possibly
    // different onBehalfOfAccount values. We show that
    // the choice of onBehalfOfAccount does not effect
    // whether or not the call reverts (i.e. it is not
    // used during authorization).
    require e.msg.sender == targetContract;
    require targetContract != currentContract;
    storage stateBeforeCall = lastStorage;
    
    call@withrevert(e, targetContract, onBehalfOfAccount1, value, data);
    bool reverts1 = lastReverted;
    // wind back execution start from the same initial state and give
    // the other onBehalfOfAccount value
    call@withrevert(e, targetContract, onBehalfOfAccount2, value, data) at stateBeforeCall;
    bool reverts2 = lastReverted;
    assert reverts1 == reverts2;

}