methods {
    function EthereumVaultConnector.checkStatusAll(TransientStorage.SetType setType) internal => GhostCheckStatusAll();
}

persistent ghost bool checkCalled;

function GhostCheckStatusAll() {
    checkCalled = true;
}

// Passing:
// https://prover.certora.com/output/65266/2523dd890b324c9cb6c1fcec767e030e?anonymousKey=5c7f3132f51538a96a5d8d4fb0de61f4ed892ccc

rule checkStatusCalled_call {
    env e;
    require checkCalled == false;
    address targetContract;
    address onBehalfOfAccount;
    uint256 value;
    bytes data;
    // Assume the initial context did not defer checks. This
    // can be checked manually by looking at the contstructor
    require !getExecutionContextAreChecksDeferred(e);
    call(e, targetContract, onBehalfOfAccount, value, data);
    assert checkCalled;
}

rule checkStatusCalled_batch {
    env e;
    calldataarg args;
    require checkCalled == false;
    // Assume the initial context did not defer checks
    require !getExecutionContextAreChecksDeferred(e);
    batch(e, args);
    assert checkCalled;
}

// Permit 
// In permit, the targetContract on which the function is called
// is hardcoded to be the EVC, so it gets converted into an ordinary
// call op with a different caller. So the rule for call covers permit
// as well.