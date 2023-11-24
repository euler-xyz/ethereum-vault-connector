
methods{
    function accountControllerContains(address base, address lookUp) external returns (bool) envfree;
    function vaultStatusCheckContains(address vault) external returns (bool) envfree;

    function getExecutionContextCallDepth() external returns (uint8) envfree;
    function getExecutionContextAreChecksDeferred() external returns (bool) envfree;
}

// variable is true if we inserted EVC as a controller anywhere
ghost bool insertedEVCAsController {
    init_state axiom insertedEVCAsController == false;
}

hook Sload address value EthereumVaultConnectorHarness.accountControllers[KEY address user].firstElement STORAGE {
    if (!insertedEVCAsController) require(value != currentContract);
}
hook Sload address value EthereumVaultConnectorHarness.accountControllers[KEY address user].elements[INDEX uint256 i].value STORAGE {
    if (!insertedEVCAsController) require(value != currentContract);
}
hook Sstore EthereumVaultConnectorHarness.accountControllers[KEY address user].firstElement address value STORAGE {
    if (value == currentContract) insertedEVCAsController = true;
}
hook Sstore EthereumVaultConnectorHarness.accountControllers[KEY address user].elements[INDEX uint256 i].value address value STORAGE {
    if (value == currentContract) insertedEVCAsController = true;
}

// variable is true if we inserted EVC as a vault for a check anywhere
ghost bool insertedEVCAsVault {
    init_state axiom insertedEVCAsVault == false;
}

hook Sload address value EthereumVaultConnectorHarness.vaultStatusChecks.firstElement STORAGE {
    if (!insertedEVCAsVault) require(value != currentContract);
}
hook Sload address value EthereumVaultConnectorHarness.vaultStatusChecks.elements[INDEX uint256 i].value STORAGE {
    if (!insertedEVCAsVault) require(value != currentContract);
}
hook Sstore EthereumVaultConnectorHarness.vaultStatusChecks.firstElement address value STORAGE {
    if (value == currentContract) insertedEVCAsVault = true;
}
hook Sstore EthereumVaultConnectorHarness.vaultStatusChecks.elements[INDEX uint256 i].value address value STORAGE {
    if (value == currentContract) insertedEVCAsVault = true;
}

//This invariant checks that account controller never contains EVC
invariant accountControllerNeverContainsEVC(address x)
    insertedEVCAsController == false;

//The batch depth is only increased internally and set back to 0 after every method execution.
//invariant batchDepthAlwaysZero()
//    getExecutionContextCallDepth() == 0;

//This invariant checks that vault status checks never contains EVC
invariant vaultStatusChecksNeverContainsEVC()    
    insertedEVCAsVault == false;
//    vaultStatusCheckContains(currentContract) == false {
//        preserved {
//            requireInvariant batchDepthAlwaysZero();
//        }
//    }

//invariant check_callDepth_zero_means_checksAreDeferred()
//    getExecutionContextCallDepth() > 0 <=> getExecutionContextAreChecksDeferred();
