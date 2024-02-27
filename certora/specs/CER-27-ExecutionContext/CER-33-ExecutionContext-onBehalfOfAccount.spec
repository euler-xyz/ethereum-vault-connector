// CER-33: Execution Context MUST keep track of the Account on behalf of which
// the current low-level external call is being performed.
import "../utils/IsLowLevelCallFunction.spec";

methods {
    function getExecutionContextOnBehalfOfAccount() external returns (address) envfree;
    // There is another callback in checkAccountStatusInternal with
    // an external vault contract as the target. We want to exclude
    // this low-level CALL from these rules, and this is the point
    // of the following summary, which excludes the CALL but models
    // an arbitrary implementation of this function.
    // CER-76 checks properties of EVC's handling of checkAccountStatusInternal
    function EthereumVaultConnector.requireAccountStatusCheckInternal(address account) internal => NONDET;
    // May not be needed / does not help, try deleting
    // function _.restoreExecutionContext(uint256) internal => NONDET;
}

// persistent ghost address callTarget;
// persistent ghost address savedOnBehalf;
persistent ghost bool callTargetCorrect;
// This is just initialized to e.msg.sender within the rule
// so it can be accessed in the hook
persistent ghost address msgSenderSavedForHook;

hook CALL(uint g, address addr, uint value, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc
{
    // callTarget = addr;
    // savedOnBehalf = getExecutionContextOnBehalfOfAccount();
    callTargetCorrect = callTargetCorrect && (
        addr == getExecutionContextOnBehalfOfAccount() ||
        addr == msgSenderSavedForHook ||
        addr == currentContract);
}

hook DELEGATECALL(uint g, address addr, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc
{
    // callTarget = addr;
    // savedOnBehalf = getExecutionContextOnBehalfOfAccount();
    callTargetCorrect = callTargetCorrect && (
        addr == getExecutionContextOnBehalfOfAccount() ||
        addr == msgSenderSavedForHook ||
        addr == currentContract);   
}

// Run each of the functions that do low-level calls.
// During the low-level calls, the hooks in this spec check whether
// the execution context was used to get the target address.
rule execution_context_tracks_account_for_calls (method f) filtered { f->
    isLowLevelCallFunction(f)
}{
    env e;
    calldataarg args;
    // We prove this is true aside from in the context of permit
    // with CER-51
    require e.msg.sender != currentContract;
    require msgSenderSavedForHook == e.msg.sender;
    // initialize ghosts
    require callTargetCorrect;
    f(e, args);
    assert callTargetCorrect;
}