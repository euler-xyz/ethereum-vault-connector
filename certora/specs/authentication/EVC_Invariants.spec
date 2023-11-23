
methods{
    function accountControllerContains(address base, address lookUp) external returns (bool) envfree;
    function vaultStatusCheckContains(address vault) external returns (bool) envfree;
}

//This invariant checks that account controller never contains EVC
invariant accountControllerNeverContainsEVC(address x)
    accountControllerContains(x, currentContract) == false;

//This invariant checks that vault status checks never contains EVC
invariant vaultStatusChecksNeverContainsEVC()    
    vaultStatusCheckContains(currentContract) == false;

