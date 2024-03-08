import "../utils/IsMustRevertFunction.spec";

// CER-78: Vault Status Check scheduling
// Only the Vault is allowed require the check for itself
methods {
    function EthereumVaultConnector.requireVaultStatusCheckInternal(address vault) internal with (env e) => requireVaultStatusCheckOnlyCalledBySelf(e, vault);
}

function requireVaultStatusCheckOnlyCalledBySelf(env e, address vault) {
    assert e.msg.sender == vault;
    requireVaultStatusCheck(e, vault);
}

rule vault_status_check_scheduling (method f) filtered { f ->
    !isMustRevertFunction(f)
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