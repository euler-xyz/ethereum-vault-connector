// CER-25: Call/Batch EVC self-call In Call and Batch. If the target is the EVC,
// the account specified MUST be / address(0) for the sake of consistency. In
// that case, the EVC MUST be delegatecalled to preserve the msg.sender and,
// depending on a function, a function-specific authentication is performed

methods {
    // TODO need to summarize restore execution context to avoid those callbacks
    // which are covered by other rules
}

persistent ghost bool reachedDelegateCall;
persistent ghost bool reachedCall;

hook CALL(uint g, address addr, uint value, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc
{
    reachedCall = true;
}

hook DELEGATECALL(uint g, address addr, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc
{
    reachedDelegateCall = true;
}

rule call_self_call {
    env e;
    address targetContract;
    address onBehalfOfAccount;
    uint256 value;
    bytes data;

    require targetContract == currentContract;
    require !reachedDelegateCall;
    require !reachedCall;
    call(e, targetContract, onBehalfOfAccount, value, data);
    assert onBehalfOfAccount == 0;
    assert reachedDelegateCall;
    assert !reachedCall;
}

rule batch_self_call {
    env e;
    IEVC.BatchItem[] items;
    require items.length == 1;
    require items[0].targetContract == currentContract;
    require !reachedDelegateCall;
    require !reachedCall;
    batch(e, items);
    assert items[0].onBehalfOfAccount == 0;
    assert reachedDelegateCall;
    assert !reachedCall;
}