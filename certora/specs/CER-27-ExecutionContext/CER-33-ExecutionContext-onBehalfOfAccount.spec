// CER-33: Execution Context MUST keep track of the Account on behalf of which
// the current low-level external call is being performed.
import "../utils/IsLowLevelCallFunction.spec";

methods {
    function getExecutionContextOnBehalfOfAccount() external returns (address) envfree;
    // May not be needed / does not help
    function _.restoreExecutionContext(uint256) internal => NONDET;
}

// persistent ghost address callTarget;
// persistent ghost address savedOnBehalf;
persistent ghost bool callTargetCorrect;

hook CALL(uint g, address addr, uint value, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc
{
    // callTarget = addr;
    // savedOnBehalf = getExecutionContextOnBehalfOfAccount();
    callTargetCorrect = callTargetCorrect && (
        addr == getExecutionContextOnBehalfOfAccount() ||
        addr == currentContract);
}

hook DELEGATECALL(uint g, address addr, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc
{
    // callTarget = addr;
    // savedOnBehalf = getExecutionContextOnBehalfOfAccount();
    callTargetCorrect = callTargetCorrect && (
        addr == getExecutionContextOnBehalfOfAccount() ||
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
    // initialize ghosts
    require callTargetCorrect;
    f(e, args);
    assert callTargetCorrect;
}