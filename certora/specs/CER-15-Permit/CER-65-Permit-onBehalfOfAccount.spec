import "../utils/IsMustRevertFunction.spec"; import
"../utils/ActualCaller.spec";

// CER-65: EVC MUST only rely on the stored Execution Context's
// onBehalfOfAccount address when in Permit context. In other words, it MUST NOT
// be possible to spoof Execution Context's onBehalfOfAccount (i.e. by using
// call in a callback manner where authentication is not performed) and force
// the EVC to rely on that spoofed address


// To specify this property, the idea here is to compare between these two 
// executions beginning from the same initial state:
// - "Harmless case": we mimic the context established in a permit() 
// call with onBehalfOfAccount = adversary, and execute a call(targetContract=addr(this), onBehalfOfAccount=adversary)
// - "Adversarial case": we mimic the context established in a permit() call with onBehalfOfAccount=victim, and execute a call(targetContract=addr(this), onBehalfOfAccount=adversary) (where victim and adversary may differ)
// We then show that in all cases where the "harmless" execution fails,
// the "adversial" case would also fail. So an attacker gannot gain more
// privilege by attempting to spoof the onBehalfOfAccount
rule cannot_spoof_onBehalfOfAccount() {
    env e_harmless;
    env e_adversarial;

    uint256 value;
    bytes data;

    address victim;
    address adversary;

    // save the initial state
    storage initialState = lastStorage;

    // Harmless case (the real onBehalfOfAccount address is the adversary's):
    // No attempt to spoof the onBehalfOfAccount is made
    require e_harmless.msg.sender == currentContract;
    require getExecutionContextOnBehalfOfAccount(e_harmless) == adversary;
    call@withrevert(e_harmless, currentContract, adversary, value, data);
    bool harmlessReverted = lastReverted;

    // Adversarial case (the real onBehalfOfAccount is the victim's):
    // An attempt to spoof the onBehalfOfAccount is made
    // (Beginning from same initial state as the harmless case)
    require e_adversarial.msg.sender == currentContract;
    require getExecutionContextOnBehalfOfAccount(e_adversarial) == victim;
    call@withrevert(e_adversarial, currentContract, adversary, 
        value, data) at initialState;
    bool adversarialReverted = lastReverted;

    // We show that in all harmless executions that are reverted,
    // the adversrial case is also reverted, so an adversary
    // cannot gain more privilege (i.e. cause more calls to succeed)
    // by attempting to spoof the onBehalfOfAccount
    assert harmlessReverted => adversarialReverted;

}