methods {
    function haveCommonOwner(
        address account,
        address otherAccount
    ) external returns(bool) envfree;

    function getAccountOwner(
        address account
    ) external returns(address) envfree;

    function getExecutionContext(
        address controllerToCheck
    )
    external
    returns(address, bool)
    envfree;

    function isAccountStatusCheckDeferred(
        address account
    ) external returns(bool) envfree;

    function isVaultStatusCheckDeferred(
        address vault
    ) external returns(bool) envfree;

    function getCollaterals(
        address account
    ) external returns(address[] memory) envfree;

    function isCollateralEnabled(
        address account,
        address vault
    ) external returns(bool) envfree;

    function isControllerEnabled(
        address account,
        address vault
    ) external returns(bool) envfree;

    // Extra methods
    function numAccountCollaterals(address account) external returns(uint8) envfree;

    function numAccountControllers(address account) external returns(uint8) envfree;

    function getOwnerLookup(uint152 prefix) external returns(address) envfree;

    function getExecutionContextIgnoringStamp() external returns(uint256) envfree;

    function getExecutionContextChecksLock() external returns(bool) envfree;

    function getExecutionContextImpersonateLock() external returns(bool) envfree;

    function getExecutionContextBatchDepth() external returns(uint8) envfree;

    function getExecutionContextBatchDepthIsInit() external returns(bool) envfree;

    function getExecutionContextOnBehalfOfAccount() external returns(address) envfree;

    function getAccountStatusChecksSize() external returns(uint8) envfree;

    function getVaultStatusChecksSize() external returns(uint8) envfree;
}

/// After a call the execution context is zeroed out
invariant executionContextIsCleared() getExecutionContextIgnoringStamp() == 0;