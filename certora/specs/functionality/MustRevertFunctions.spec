//Tests for a set of functions that have at least one input for which the function MUST not revert.
rule nonRevertingFunctions(method f) filtered {f -> !isMustRevertingFunction(f)} {
    env e; calldataarg args;

    f(e,args);
    satisfy true, "The function always reverts.";
}

//Tests for the set of functions that MUST revert for all inputs.
rule mustRevertFunctions(method f) filtered {f -> isMustRevertingFunction(f)} {
    env e; calldataarg args;

    f@withrevert(e,args);
    assert lastReverted == true, "The function must revert for every input.";
}

//Definition of the set of reverting functions
definition isMustRevertingFunction(method f) returns bool =
    f.selector == sig:EthereumVaultConnectorHarness.batchSimulation(IEVC.BatchItem[]).selector ||
    f.selector == sig:EthereumVaultConnectorHarness.batchRevert(IEVC.BatchItem[]).selector;