import "../utils/IsMustRevertFunction.spec";

// CER-78: Vault Status Check scheduling
// Only the Vault is allowed require the check for itself
methods {
    function EthereumVaultConnector.requireVaultStatusCheckInternal(address vault) internal with (env e) => requireVaultStatusCheckOnlyCalledBySelf(e, vault);
    // For the calls that allow deferred checks (call, batch, 
    // controlCollateral), we cannot prove that the
    // when the deferred checks are executed at the end of the deferred check
    // call that the set of vault addresses did not already contain
    // some vault address other than e.msg.sender.
    // These summaries exclude the deferred checks from the rule.
    function EthereumVaultConnector.checkStatusAll(TransientStorage.SetType setType) internal => NONDET;
    function EthereumVaultConnector.restoreExecutionContext(ExecutionContext.EC ec) internal => NONDET;
}

// In all contexts where requireVaultStatusCheckInternal is called,
// the caller should be the vault. 
persistent ghost bool onlyVault;
function requireVaultStatusCheckOnlyCalledBySelf(env e, address vault) {
    onlyVault = onlyVault &&  e.msg.sender == vault;
}

rule vault_status_check_scheduling (method f) filtered { f ->
    !isMustRevertFunction(f)
}{
    env e;
    calldataarg args;
    // The point of this rule is to check that in all contexts in which 
    // requireVaultStatusCheck is called, the vault is the message sender.
    // If requireVaultStatusCheck is reachable from the function called
    // it will modify the ghost if this is not true.
    // Assume initially the ghost variable is false
    require onlyVault;
    // Run the function which may reach requireVaultStatusCheck 
    // invoking the summary.
    f(e, args);
    // Check: we have never run requireVaultStatusCheck with the wrong sender.
    assert onlyVault;
}