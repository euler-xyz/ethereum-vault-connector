import "../utils/IsMustRevertFunction.spec";

// CER-78: Vault Status Check scheduling
// Only the Vault is allowed require the check for itself
methods {
    function EthereumVaultConnector.requireVaultStatusCheckInternal(address vault) internal with (env e) => requireVaultStatusCheckOnlyCalledBySelf(e, vault);
}

// In all contexts where requireVaultStatusCheckInternal is called,
// the caller should be the vault. 
persistent ghost bool onlyVault;
function requireVaultStatusCheckOnlyCalledBySelf(env e, address vault) {
    onlyVault = onlyVault &&  e.msg.sender == vault;
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