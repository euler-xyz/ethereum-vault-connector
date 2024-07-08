methods {
    function EthereumVaultConnector.checkStatusAll(TransientStorage.SetType setType) internal => GhostCheckStatusAll();
}

persistent ghost bool checkCalled;

function GhostCheckStatusAll() {
    checkCalled = true;
}

rule checkStatusCalled_call {
    env e;
    require checkCalled == false;
    address targetContract;
    address onBehalfOfAccount;
    uint256 value;
    bytes data;
    // Assume the initiall context did not defer checks. This
    // can be checked manually by looking at the contstructor
    require !getExecutionContextAreChecksDeferred(e);
    call(e, targetContract, onBehalfOfAccount, value, data);
    assert checkCalled;
}

rule checkStatusCalled_permit {
    env e;
    calldataarg args;

    require checkCalled == false;
    // Assume the initiall context did not defer checks
    require !getExecutionContextAreChecksDeferred(e);
    permit(e, args);
    assert checkCalled;
}

rule checkStatusCalled_batch {
    env e;
    calldataarg args;
    require checkCalled == false;
    // Assume the initiall context did not defer checks
    require !getExecutionContextAreChecksDeferred(e);
    batch(e, args);
    assert checkCalled;
}