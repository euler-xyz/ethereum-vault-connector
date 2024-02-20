import "../utils/IsMustRevertFunction.spec";
import "../utils/CallOpSanity.spec";
import "../utils/ActualCaller.spec";

// CER-16: The authorization rules of the Permit message calldata execution 
// MUST be as if the calldata were executed on the EVC directly

function same_except_sender(env e1, env e2) {
    require e1.msg.value == e2.msg.value;
    require e1.block.basefee == e2.block.basefee;
    require e1.block.coinbase == e2.block.coinbase;
    require e1.block.difficulty == e2.block.difficulty;
    require e1.block.gaslimit == e2.block.gaslimit;
    require e1.block.number == e2.block.number;
    require e1.block.timestamp == e2.block.timestamp;
    require e1.tx.origin == e2.tx.origin;
}

rule auth_rules_of_permit {
    env e_permit;
    env e_direct;
    address signer;
    uint256 nonceNamespace;
    uint256 nonce;
    uint256 deadline;
    uint256 value;
    bytes data;
    bytes signature;

    // We need to compare between 2 executions of EVC beginning from
    // the same state. To do so, we save the state before executing
    // a permit call with this line.
    storage stateBeforePermit = lastStorage;
    same_except_sender(e_permit, e_direct);

    // We execute a permit call with these arguments and save
    // whether or not the call reverted.
    permit@withrevert(e_permit, signer, nonceNamespace, nonce, deadline,
        value, data, signature);
    bool permitReverted = lastReverted;

    // We now roll back to the state before the permit
    // so we can run the call directly  on the same initial state
    // and check whether it succeeds.
    // We use the signer from the permit call as the actualCaller
    // for the call.
    require actualCaller(e_direct) == signer;
    // require e_direct.msg.sender == signer;
    require e_direct.msg.sender != currentContract;
    bool success = selfCallSuccessCheck(e_direct, value, data) at stateBeforePermit;

    // If signer directly executing the call on EVC would have 
    // resulted in a reverted call, then attempting to do the same
    // with permit would also be reverted.
    assert !success => permitReverted;

}