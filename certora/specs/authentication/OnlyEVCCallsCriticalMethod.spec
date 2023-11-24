
methods{
    function accountControllerContains(address base, address lookUp) external returns (bool) envfree;
}

ghost bool callOpCodeHasBeenCalledWithEVC;

rule onlyEVCCanCallCriticalMethod(method f, env e, calldataarg args){
    //Exclude EVC as being the initiator of the call.
    require(e.msg.sender != currentContract);
    require(callOpCodeHasBeenCalledWithEVC == false);
    //Call all contract methods
    f(e,args);

    assert callOpCodeHasBeenCalledWithEVC == false, "Only EVC can call critical method.";
}

hook CALL(uint g, address addr, uint value, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc {
    //e.msg.sender is equal to EVC, switch the flag.
    if(addr == currentContract){
        callOpCodeHasBeenCalledWithEVC = true;
    }
}

//Models invariant `accountControllerNeverContainsEVC` from file EVC_Invariants.spec using a hook on the sets.
hook Sload address value EthereumVaultConnectorHarness.accountControllers[KEY address user].firstElement STORAGE {
    require value != currentContract;
}

//Models invariant `vaultStatusChecksNeverContainsEVC` from file EVC_Invariants.spec using a hook on the sets.
hook Sload address value EthereumVaultConnectorHarness.vaultStatusChecks.firstElement STORAGE {
    require value != currentContract;
}
