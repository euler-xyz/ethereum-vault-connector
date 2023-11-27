
// variable is true if we inserted EVC as a controller anywhere
ghost bool insertedEVCAsController {
    init_state axiom insertedEVCAsController == false;
}

// when writing to accountControllers, check that value != currentContract
hook Sstore EthereumVaultConnectorHarness.accountControllers[KEY address user].firstElement address value STORAGE {
    if (value == currentContract) insertedEVCAsController = true;
}
hook Sstore EthereumVaultConnectorHarness.accountControllers[KEY address user].elements[INDEX uint256 i].value address value STORAGE {
    if (value == currentContract) insertedEVCAsController = true;
}
// when loading from accountControllers, we know that value != currentContract
hook Sload address value EthereumVaultConnectorHarness.accountControllers[KEY address user].firstElement STORAGE {
    if (!insertedEVCAsController) require(value != currentContract);
}
hook Sload address value EthereumVaultConnectorHarness.accountControllers[KEY address user].elements[INDEX uint256 i].value STORAGE {
    if (!insertedEVCAsController) require(value != currentContract);
}

// variable is true if we inserted EVC as a vault for a check anywhere
ghost bool insertedEVCAsVault {
    init_state axiom insertedEVCAsVault == false;
}

// when writing to vaultStatusChecks, check that value != currentContract
hook Sstore EthereumVaultConnectorHarness.vaultStatusChecks.firstElement address value STORAGE {
    if (value == currentContract) insertedEVCAsVault = true;
}
hook Sstore EthereumVaultConnectorHarness.vaultStatusChecks.elements[INDEX uint256 i].value address value STORAGE {
    if (value == currentContract) insertedEVCAsVault = true;
}
// when loading from vaultStatusChecks, we know that value != currentContract
hook Sload address value EthereumVaultConnectorHarness.vaultStatusChecks.firstElement STORAGE {
    if (!insertedEVCAsVault) require(value != currentContract);
}
hook Sload address value EthereumVaultConnectorHarness.vaultStatusChecks.elements[INDEX uint256 i].value STORAGE {
    if (!insertedEVCAsVault) require(value != currentContract);
}

hook CALL(uint g, address addr, uint value, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc {
    //e.msg.sender is equal to EVC, switch the flag.
    callOpCodeHasBeenCalledWithEVC = callOpCodeHasBeenCalledWithEVC || 
        (executingContract == currentContract && addr == currentContract);
}

// This invariant checks that account controller never contains EVC
invariant accountControllerNeverContainsEVC(address x)
    insertedEVCAsController == false;

// This invariant checks that vault status checks never contains EVC
invariant vaultStatusChecksNeverContainsEVC()
    insertedEVCAsVault == false
    { preserved with (env e) { require e.msg.sender != currentContract; } }

ghost bool callOpCodeHasBeenCalledWithEVC;

rule onlyEVCCanCallCriticalMethod(method f, env e, calldataarg args, address x){
    requireInvariant accountControllerNeverContainsEVC(x);
    requireInvariant vaultStatusChecksNeverContainsEVC();
    //Exclude EVC as being the initiator of the call.
    require(e.msg.sender != currentContract);
    require(callOpCodeHasBeenCalledWithEVC == false);
    //Call all contract methods
    f(e,args);

    assert callOpCodeHasBeenCalledWithEVC == false, "Only EVC can call critical method.";
}
