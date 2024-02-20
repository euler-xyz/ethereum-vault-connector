import "../utils/ActualCaller.spec";
import "../utils/IsMustRevertFunction.spec";

methods {
    function _.getOnBehalfOfAccount(uint256 ec) internal with (env e) => getOnBehalfOfAccountCheckInEVC(e, ec) expect (address);
}

// CER-65: EVC MUST only rely on the stored Execution Context's
// onBehalfOfAccount address when in Permit context. In other words, it MUST NOT
// be possible to spoof Execution Context's onBehalfOfAccount (i.e. by using
// call in a callback manner where authentication is not performed) and force
// the EVC to rely on that spoofed address

function getOnBehalfOfAccountCheckInEVC(env e, uint256 ec) returns address {
    assert e.msg.sender == currentContract;
    return ecGetOnBehalfOfAccount(e, ec);
}

rule onBehalfOfAccountOnlyInPermit(method f) filtered { f ->
    !isMustRevertFunction(f) &&
    f.selector != sig:EthereumVaultConnectorHarness.getCurrentOnBehalfOfAccount(address).selector
}{
    env e;
    calldataarg args;
    // This will execute every function in EthereumVaultConnector while 
    // replacing every call to ExecutionContext.getOnBehalfOfAccount with
    // the CVL function above. As a result, this will cause a violation
    // if this is ever called with e.msg.sender != currentContract
    f(e, args);
    // The following line is only here because rules must end in either
    // satisfy or assert. The useful part of this rule is in the summary
    // for getOnBehalfOfAccount
    satisfy true;
}

// Show that if we are within the context of a permit
// with onBehalfOfAccount == victim in the execution context,
// and an adversary attempts to execute a call with a different
// onbehalf of address, the call will revert
rule cannot_spoof_onBehalfOfAccount_call() {
    env e;
    address victim; // the real onBehalfOfAccount
    address adversary; // a spoofed, nonzero onBehalfOfAccount
    require victim != adversary;
    require adversary != 0;

    // Setup the context of a permit with onBehalfOfAccount == victim
    require e.msg.sender == currentContract;
    require getExecutionContextOnBehalfOfAccount(e) == victim;

    // Attempt a call with a different nonzero onBehalfOfAccount
    uint256 value;
    bytes data;
    call@withrevert(e, currentContract, adversary, value, data);
    assert lastReverted;
}

rule cannot_spoof_onBehalfOfAccount_batch() {
    env e;
    address victim; // the real onBehalfOfAccount
    address adversary; // a spoofed, nonzero onBehalfOfAccount
    require victim != adversary;
    require adversary != 0;

    // Setup the context of a permit with onBehalfOfAccount == victim
    require e.msg.sender == currentContract;
    require getExecutionContextOnBehalfOfAccount(e) == victim;

    // Execute a batch() where one of the arguments is a
    // BatchItem with a spoofed onBehalfOfAccount
    IEVC.BatchItem[] items;
    uint256 i;
    require 0 <= i;
    require i < items.length;
    require items[i].onBehalfOfAccount == adversary;
    require items[i].targetContract == currentContract;
    batch@withrevert(e, items);
    assert lastReverted;

}