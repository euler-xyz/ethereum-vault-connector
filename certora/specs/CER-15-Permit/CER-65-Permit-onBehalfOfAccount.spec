import "../utils/IsMustRevertFunction.spec"; import
"../utils/ActualCaller.spec";

// CER-65: EVC MUST only rely on the stored Execution Context's
// onBehalfOfAccount address when in Permit context. In other words, it MUST NOT
// be possible to spoof Execution Context's onBehalfOfAccount (i.e. by using
// call in a callback manner where authentication is not performed) and force
// the EVC to rely on that spoofed address

// Show that if we are within the context of a permit
// with onBehalfOfAccount == victim in the execution context,
// and an adversary attempts to execute a call with a different
// onbehalf of address, the call will revert
rule cannot_spoof_onBehalfOfAccount2() {
    env e;
    uint256 value;
    bytes data;
    address victim;
    address adversary;
    // Setup the context of a permit with onBehalfOfAccount == victim
    require e.msg.sender == currentContract;
    require getExecutionContextOnBehalfOfAccount(e) == victim;
    // Attempt a call with a different nonzero onBehalfOfAccount
    require victim != adversary;
    require adversary != 0;
    call@withrevert(e, currentContract, adversary, value, data);
    assert lastReverted;
}