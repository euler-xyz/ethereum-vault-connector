// CER-25: Call/Batch EVC self-call In Call and Batch. If the target is the EVC,
// the account specified MUST be / address(0) for the sake of consistency. In
// that case, the EVC MUST be delegatecalled to preserve the msg.sender and,
// depending on a function, a function-specific authentication is performed

methods {
}

rule call_self_call {
    env e;
    address targetContract;
    address onBehalfOfAccount;
    uint256 value;
    bytes data;

    require targetContract == currentContract;
    call(e, targetContract, onBehalfOfAccount, value, data);
    assert onBehalfOfAccount == 0;
}

rule batch_self_call {
    env e;
    IEVC.BatchItem[] items;
    require items.length == 1;
    require items[0].targetContract == currentContract;
    batch(e, items);
    assert items[0].onBehalfOfAccount == 0;
}