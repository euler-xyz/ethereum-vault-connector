using CreditVaultStub as CreditVaultStub;

methods {
    /// @dev envfree functions in CreditVaultConnector.sol
    function PERMIT_TYPEHASH() external returns (bytes32) envfree;
    function getAccountOperator(address,address) external returns (uint256) envfree;
    function getAccountOwner(address) external returns (address) envfree;
    function getCollaterals(address) external returns (address[]) envfree;
    function getControllers(address) external returns (address[]) envfree;
    function getExecutionContext(address) external returns (address, bool) envfree;
    function getNonce(address,uint256) external returns (uint256) envfree;
    function getRawExecutionContext() external returns (uint256) envfree;
    function haveCommonOwner(address,address) external returns (bool) envfree;
    function isAccountStatusCheckDeferred(address) external returns (bool) envfree;
    function isCollateralEnabled(address,address) external returns (bool) envfree;
    function isControllerEnabled(address,address) external returns (bool) envfree;
    function isVaultStatusCheckDeferred(address) external returns (bool) envfree;
    function name() external returns (string) envfree;
    function version() external returns (string) envfree;

    /// @dev envfree functions in CreditVaultConnectorHarness.sol
    function callHandler_wasHit() external returns (bool) envfree;
    function callHandler_doRevert() external returns (bool) envfree;
    function callHandler_doCheckMsgSender() external returns (bool) envfree;
    function callHandler_checkedMsgSender() external returns (address) envfree;
    function numAccountCollaterals(address account) external returns (uint8) envfree;
    function numAccountControllers(address account) external returns (uint8) envfree;
    function getOwnerLookup(uint152 prefix) external returns (address) envfree;
    function getExecutionContextIgnoringStamp() external returns (uint256) envfree;
    function getExecutionContextChecksLock() external returns (bool) envfree;
    function getExecutionContextImpersonateLock() external returns (bool) envfree;
    function getExecutionContextBatchDepth() external returns (uint8) envfree;
    function getExecutionContextBatchDepthIsInit() external returns (bool) envfree;
    function getExecutionContextOnBehalfOfAccount() external returns (address) envfree;
    function getAccountStatusChecksSize() external returns (uint8) envfree;
    function getVaultStatusChecksSize() external returns (uint8) envfree;
}

definition alwaysReverts(method f) returns bool = 
	f.selector == sig:batchSimulation(ICVC.BatchItem[]).selector ||
	f.selector == sig:batchRevert(ICVC.BatchItem[]).selector;

definition ignoredMethod(method f) returns bool = 
    f.isView || f.isPure || f.selector == sig:callHandler(bytes).selector || alwaysReverts(f);

/// After a call the execution context is zeroed out
invariant executionContextIsCleared() 
    getExecutionContextIgnoringStamp() == 0
    filtered {f -> !ignoredMethod(f)}

/// @dev the only way for msg.sender to be equal to address(this) in any of the external functions is when we pass through the permit() and self-call
rule callerIsCVCOnlyThroughPermit(env e, method f, calldataarg args) 
filtered {f -> !ignoredMethod(f)} {
    require(e.msg.sender != currentContract);
    require(!callHandler_wasHit());
    require(callHandler_doCheckMsgSender());
    require(callHandler_checkedMsgSender() == currentContract);

    f(e, args);

    assert callHandler_wasHit() => f.selector == sig:permit(address,uint256,uint256,bytes,bytes).selector;
}

/// @dev verify that the call resolution works as intended 
rule callerIsCVCOnlyThroughPermit_sanity(env e, calldataarg args) {
    require(e.msg.sender != currentContract);
    require(!callHandler_wasHit());
    require(callHandler_doCheckMsgSender());
    require(callHandler_checkedMsgSender() == currentContract);

    permit(e, args);

    satisfy callHandler_wasHit();
}