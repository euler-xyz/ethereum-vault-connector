methods {
    function haveCommonOwner(
        address account,
        address otherAccount
    ) external returns (bool) envfree;

    function getAccountOwner(
        address account
    ) external returns (address) envfree;

    function getExecutionContext(
        address controllerToCheck
    )
        external
        returns (ICVC.ExecutionContext memory, bool)
        envfree;

    function isAccountStatusCheckDeferred(
        address account
    ) external returns (bool) envfree;

    function isVaultStatusCheckDeferred(
        address vault
    ) external returns (bool) envfree;

    function getCollaterals(
        address account
    ) external returns (address[] memory) envfree;

    function isCollateralEnabled(
        address account,
        address vault
    ) external returns (bool) envfree;

    function getControllers(
        address account
    ) external returns (address[] memory) envfree;

    function isControllerEnabled(
        address account,
        address vault
    ) external returns (bool) envfree;

    // Extra methods
    function numAccountCollaterals(address account) external returns (uint8) envfree;

    function numAccountControllers(address account) external returns (uint8) envfree;

    function getOwnerLookup(uint152 prefix) external returns (address) envfree;

    function getExecutionContext() external returns (ICVC.ExecutionContext) envfree;

    function getExecutionContextChecksLock() external returns (bool) envfree;

    function getExecutionContextImpersonateLock() external returns (bool) envfree;

    function getExecutionContextBatchDepth() external returns (uint8) envfree;

    function getExecutionContextOnBehalfOfAccount() external returns (address) envfree;

    function getAccountStatusChecks() external returns (CreditVaultConnectorHarness.SetStorage) envfree;

    function getAccountStatusChecksSize() external returns (uint8) envfree;

    function getVaultStatusChecks() external returns (CreditVaultConnectorHarness.SetStorage) envfree;

    function getVaultStatusChecksSize() external returns (uint8) envfree;

    function isAccountOperator(address account, address operator) external returns (bool) envfree;
}


// struct ExecutionContext {
//     uint8 batchDepth;
//     bool checksLock;
//     bool impersonateLock;
//     address onBehalfOfAccount;
//     uint8 reserved;
// }
// definition ExecutionContext_batchDepth(uint256 s) returns uint256 =
//     s & 0xffffffffffffffffffffffffffffffff;

invariant executionContextIsCleaned() 
    getExecutionContextChecksLock() == false
    && getExecutionContextImpersonateLock() == false
    && getExecutionContextBatchDepth() == 0 
    && getExecutionContextOnBehalfOfAccount() == 0 
    && getAccountStatusChecksSize() == 0 
    && getVaultStatusChecksSize() == 0;

invariant controllersAreZeroOrOne(address account)
    numAccountControllers(account) <= 1;

rule controllersAreZeroOrOne(env e, method f, calldataarg args, address account) {
    require(getExecutionContextBatchDepth() == 0);
    require(numAccountControllers(account) <= 1);
    f(e, args);
    require(numAccountControllers(account) <= 1);
}

/*
    @Rule

    @Description:
        If account owner is set once, it cannot be changed anymore.

    @Note:
        This is property 1 of the CVC Specification.
    @Link:
*/
rule groupOwnerIsOneWay(env e, method f, calldataarg args, address account) {
    address originalOwner = getAccountOwner(account);
    
    require(originalOwner != 0);
    f(e, args);
    assert getAccountOwner(account) == originalOwner;
}

/*
    @Rule

    @Description:
        Only an Account Owner can grant permission to an Account Operator to operate on behalf of the Account.

    @Note:
        This is property 2 of the CVC Specification.
    @Link:
*/
rule onlyOwnerCanGrantOperatorship(env e, method f, calldataarg args, address account, address operator) {
    require(e.msg.sender != account);

    bool isOperatorBefore = isAccountOperator(account, operator);
    f(e, args);
    bool isOperatorAfter = isAccountOperator(account, operator);

    assert isOperatorAfter == isOperatorBefore;
}

/// 6. (part) Only an Account Owner can grant permission to an Account Operator to operate on behalf of the Account.
rule onlyOwnerOrOperatorCanMutateCollateralVaultSet(env e, method f, calldataarg args, address account) {
    // msg.sender is not owner
    require(!haveCommonOwner(account, e.msg.sender));
    
    // msg.sender is not an operator
    require(!isAccountOperator(account, e.msg.sender));

    uint8 collateralsBefore = numAccountCollaterals(account);
    f(e, args);
    uint8 collateralsAfter = numAccountCollaterals(account);

    assert collateralsBefore == collateralsAfter;
}

/// 7. Only an Account Owner or the Account Operator can enable a Controller Vault for the Account.
rule onlyOwnerOrOperatorCanEnableCollateralVault(env e, method f, calldataarg args, address account, address vault) {
    // msg.sender is not owner
    require(!haveCommonOwner(account, e.msg.sender));
    
    // msg.sender is not an operator
    require(!isAccountOperator(account, e.msg.sender));

    // vault is not enabled
    require(!isControllerEnabled(account, vault));

    f(e, args);

    // vault is still not enabled
    assert !isControllerEnabled(account, vault);
}

/// 8. Only a Controller Vault can disable itself for the Account.
rule onlyControllerVaultCanDisableItself(env e, method f, calldataarg args, address account, address vault) {
    // msg.sender is not controller for account
    require(!isControllerEnabled(account, e.msg.sender));
    // vault is controller for account
    require(isControllerEnabled(account, vault));

    f(e, args);

    // vault is still controller for account
    assert isControllerEnabled(account, vault);
}

hook Sstore s_1.(offset 16) uint64 second (uint64 old_second) STORAGE {
  // hook body
}

/// 10. If there's only one enabled Controller Vault for an Account, only that Controller can impersonate the Account's call into any of its enabled Collateral Vaults
rule onlySoleControllerCanImpersonate(env e, method f, calldataarg args, address account) {
    // msg.sender is controller for account
    require(isControllerEnabled(account, e.msg.sender));

    // ch
    uint8 numControllers = numAccountControllers();
    impersonate(e, args);

    // vault is still controller for account
    assert isControllerEnabled(account, vault);
}
