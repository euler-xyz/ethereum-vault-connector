
methods{
    function accountControllerContains(address base, address lookUp) external returns (bool) envfree;
    function isVaultStatusCheckDeferred(address vault) external returns (bool) envfree;
}


invariant accountControllerNeverContainsEVC(address x)
    accountControllerContains(x, currentContract) == false;

invariant canEVCBeInStatusChecks()    
    isVaultStatusCheckDeferred(currentContract) == false;

