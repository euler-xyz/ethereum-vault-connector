
//Definition of the set of reverting functions
definition isMustRevertFunction(method f) returns bool =
    f.selector == sig:EthereumVaultConnectorHarness.batchSimulation(IEVC.BatchItem[]).selector ||
    f.selector == sig:EthereumVaultConnectorHarness.batchRevert(IEVC.BatchItem[]).selector;
