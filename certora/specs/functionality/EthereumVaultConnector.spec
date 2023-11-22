
methods{
    function getExecutionContextCallDepth() external returns (uint8) envfree;
    function getExecutionContextAreChecksDeferred() external returns (bool) envfree;
}

//checks that all EVC checks are deferred iff the contract is in call depth > 0
//TODO: Rule fails on method `enableController` in a rule error: See https://certora.atlassian.net/jira/software/c/projects/CERT/issues/CERT-4160.
invariant check_callDepth_zero_means_checksAreDeferred()
    getExecutionContextCallDepth() > 0 <=> getExecutionContextAreChecksDeferred();
