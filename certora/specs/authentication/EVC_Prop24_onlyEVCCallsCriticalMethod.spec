import "../utils/IsMustRevertFunction.spec";

////////////////////////////////////////////////////////////////
//                                                            //
//           Account Controllers (Ghost and Hooks)            //
//                                                            //
////////////////////////////////////////////////////////////////


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

////////////////////////////////////////////////////////////////
//                                                            //
//           Vault Status Checks (Ghost and Hooks)            //
//                                                            //
////////////////////////////////////////////////////////////////

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

////////////////////////////////////////////////////////////////
//                                                            //
//                Ghost and Hook for Property                 //
//  EVC can only be msg.sender during the permit() function   //
//                                                            //
////////////////////////////////////////////////////////////////

// variable is true when a call was made with e.msg.sender == EVC
ghost bool callOpCodeHasBeenCalledWithEVC;

// hook applied to every call, updates the ghost.
hook CALL(uint g, address addr, uint value, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc {
    //e.msg.sender is equal to EVC (currentContract and exeuctingContract), switch the flag.
    callOpCodeHasBeenCalledWithEVC = callOpCodeHasBeenCalledWithEVC || 
        (executingContract == currentContract && addr == currentContract);
}

// hook applied to every delegatecall updating the ghost when EVC
hook DELEGATECALL(uint g, address addr, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc {
    callOpCodeHasBeenCalledWithEVC = callOpCodeHasBeenCalledWithEVC || addr != currentContract; 
}
////////////////////////////////////////////////////////////////
//                                                            //
//                         Invariants                         //
//                                                            //
////////////////////////////////////////////////////////////////

// This invariant checks that account controller never contains EVC
invariant accountControllerNeverContainsEVC()
    insertedEVCAsController == false
    filtered {f -> !isMustRevertFunction(f)}

// This invariant checks that vault status checks never contains EVC
invariant vaultStatusChecksNeverContainsEVC()
    insertedEVCAsVault == false
    filtered {f -> !isMustRevertFunction(f)}
    { preserved with (env e) { require e.msg.sender != currentContract; } }

// This rule checks the property of interest "EVC can only be msg.sender during the self-call in the permit() function". Expected to fail on permit() function.
rule onlyEVCCanCallCriticalMethod(method f, env e, calldataarg args)
  filtered {f -> 
    !isMustRevertFunction(f) &&
    f.selector != sig:EthereumVaultConnectorHarness.permit(address,uint256,uint256,uint256,uint256,bytes,bytes).selector
  }{
    //Exclude EVC as being the initiator of the call.
    require(e.msg.sender != currentContract);

    //Require the invariants to hold
    requireInvariant vaultStatusChecksNeverContainsEVC();
    requireInvariant accountControllerNeverContainsEVC();

    //Require the ghost flag to be false initially
    require(!callOpCodeHasBeenCalledWithEVC);
    //Call all contract methods
    f(e,args);

    //Ensure the ghost flag to be false eventually
    assert !callOpCodeHasBeenCalledWithEVC, "Only EVC can call critical method.";
}


