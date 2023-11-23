
methods{
    function accountControllerContains(address base, address lookUp) external returns (bool) envfree;
    function vaultStatusCheckContains(address vault) external returns (bool) envfree;
        
    function getExecutionContextCallDepth() external returns (uint8) envfree;
    function getExecutionContextAreChecksDeferred() external returns (bool) envfree;
}

//This invariant checks that account controller never contains EVC
invariant accountControllerNeverContainsEVC(address x)
    accountControllerContains(x, currentContract) == false;

//The batch depth is only increased internally and set back to 0 after every method execution.
invariant batchDepthAlwaysZero()
    getExecutionContextCallDepth() == 0;

//This invariant checks that vault status checks never contains EVC
invariant vaultStatusChecksNeverContainsEVC()    
    vaultStatusCheckContains(currentContract) == false {
        preserved {
            requireInvariant batchDepthAlwaysZero();
        }
    }

invariant check_callDepth_zero_means_checksAreDeferred()
    getExecutionContextCallDepth() > 0 <=> getExecutionContextAreChecksDeferred();
