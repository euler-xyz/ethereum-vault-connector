
methods{
    function getExecutionContextCallDepth() external returns (uint8) envfree;
    function getExecutionContextAreChecksDeferred() external returns (bool) envfree;

    function getAddressPrefix(address) external returns (uint152) envfree;
    function haveCommonOwner(address, address) external returns (bool) envfree;
}

//checks that all EVC checks are deferred iff the contract is in call depth > 0
//TODO: Rule fails on method `enableController` in a rule error: See #4160.
invariant check_callDepth_zero_means_checksAreDeferred()
    getExecutionContextCallDepth() > 0 <=> getExecutionContextAreChecksDeferred();

//check that to addresses with the same prefix also have a common owner
rule check_have_commonPrefix(){
    address x;
    address y;
    uint152 prefixX = getAddressPrefix(x);
    uint152 prefixY = getAddressPrefix(y);

    bool haveCommonOwner = haveCommonOwner(x,y);

    assert haveCommonOwner <=> prefixX == prefixY;
}
