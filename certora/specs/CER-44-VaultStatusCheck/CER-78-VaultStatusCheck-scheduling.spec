import "../utils/IsMustRevertFunction.spec";

// CER-78: Vault Status Check scheduling
// Only the Vault is allowed require the check for itself
methods {
    function EthereumVaultConnector.requireVaultStatusCheckInternal(address vault) internal with (env e) => requireVaultStatusCheckOnlyCalledBySelf(e, vault);
    // This summarization does not work see note
    // function EthereumVaultConnector.callWithContextInternal(address targetContract, address onBehalfOfAccount, uint256 value, bytes calldata data) internal returns (bool, bytes memory) => NONDET;
    // function EthereumVaultConnector.callWithContextInternal(address targetContract, address onBehalfOfAccount, uint256 value, bytes calldata data) internal returns (bool, bytes memory) => CallWithContextInternalSummary(targetContract, onBehalfOfAccount, value, data);

}

/*
 * This summarization does not work:
 CRITICAL: [main] ERROR ALWAYS - Error in spec file (CER-78-VaultStatusCheck-scheduling.spec:15:9): could not type expression "CallResult(targetContract, onBehalfOfAccount, value, convert_hashblob(data))", message: Expected type bytes in return position 2 of CVL function CallWithContextInternalSummary, but CallResult(targetContract, onBehalfOfAccount, value, convert_hashblob(data)) is of type hashblob
*/
// function CallWithContextInternalSummary(address targetContract, address onBehalfOfAccount, uint256 value, bytes data) returns (bool, bytes) {
//     return (
//         CallSuccess(targetContract, onBehalfOfAccount, value, data),
//         CallResult(targetContract, onBehalfOfAccount, value, data)
//     );
// }
// ghost CallSuccess(address, address, uint256, bytes) returns bool;
// ghost CallResult(address, address, uint256, bytes) returns bytes;


// NOTE: not used. delete or refactor if it becomes used
function actualCaller(env e) returns address {
    if(e.msg.sender == currentContract) {
        return getExecutionContextOnBehalfOfAccount(e);
    } else {
        return e.msg.sender;
    }
}

// In all contexts where requireVaultStatusCheckInternal is called,
// the caller should be the vault. 
function requireVaultStatusCheckOnlyCalledBySelf(env e, address vault) {
    assert e.msg.sender == vault;
}

rule vault_status_check_scheduling (method f) filtered { f ->
    !isMustRevertFunction(f)
    // These functions we have trouble reasoning about because
    // they involve callWithContextInternal
    && f.selector != sig:batch(IEVC.BatchItem[] calldata).selector
    && f.selector != sig:call(address, address, uint256, bytes calldata).selector
    && f.selector != sig:controlCollateral(address, address, uint256, bytes).selector
}{
    env e;
    calldataarg args;
    // The point of this rule is to check that in all contexts in which 
    // requireVaultStatusCheck is called, the vault is the message sender
    // If requireVaultStatusCheck is reachable from the function called
    // it will invoke the assertion in requireVaultStatusCheckOnlyCalledBySelf
    f(e, args);
    // This is just here to make this a valid rule
    satisfy true;
}