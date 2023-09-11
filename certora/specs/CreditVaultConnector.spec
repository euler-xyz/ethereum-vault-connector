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

    function getExecutionContextChecksLock() external returns (bool) envfree;

    function getExecutionContextImpersonateLock() external returns (bool) envfree;

    function getExecutionContextBatchDepth() external returns (uint8) envfree;

    function getExecutionContextOnBehalfOfAccount() external returns (address) envfree;

    function getAccountStatusChecksSize() external returns (uint8) envfree;

    function getVaultStatusChecksSize() external returns (uint8) envfree;

    function isAccountOperator(address account, address operator) external returns (bool) envfree;
}

definition isHelperMethod(method f) returns bool = 
    f.selector == sig:numAccountCollaterals(address).selector
    || f.selector == sig:numAccountControllers(address).selector
    || f.selector == sig:getOwnerLookup(uint152).selector
    || f.selector == sig:getExecutionContextChecksLock().selector
    || f.selector == sig:getExecutionContextImpersonateLock().selector
    || f.selector == sig:getExecutionContextBatchDepth().selector
    || f.selector == sig:getExecutionContextOnBehalfOfAccount().selector
    || f.selector == sig:getAccountStatusChecksSize().selector
    || f.selector == sig:getVaultStatusChecksSize().selector
    || f.selector == sig:isAccountOperator(address, address).selector;

function requireClearExecutionContext() {
  require getExecutionContextChecksLock() == false
    && getExecutionContextImpersonateLock() == false
    && getExecutionContextBatchDepth() == 0 
    && getExecutionContextOnBehalfOfAccount() == 0 
    && getAccountStatusChecksSize() == 0 
    && getVaultStatusChecksSize() == 0;
}

/// After a call the execution context is zeroed out
invariant executionContextIsCleared() 
    getExecutionContextChecksLock() == false
    && getExecutionContextImpersonateLock() == false
    && getExecutionContextBatchDepth() == 0 
    && getExecutionContextOnBehalfOfAccount() == 0 
    && getAccountStatusChecksSize() == 0 
    && getVaultStatusChecksSize() == 0;

/// A batchRevert call always reverts
rule batchRevertAlwaysReverts(env e, calldataarg args) {
    batchRevert@withrevert(e, args);

    assert lastReverted;
}


/// 1. If account owner is set once, it cannot be changed anymore.
rule groupOwnerCanBeSetOnce(env e, method f, calldataarg args, address account) 
filtered {
  f -> !isHelperMethod(f)  
} {
    requireClearExecutionContext();
    address originalOwner = getAccountOwner(account);
    require(originalOwner != 0);

    f(e, args);

    assert getAccountOwner(account) == originalOwner;
}

/// 2. Only an Account Owner can grant permission to an Account Operator to operate on behalf of the Account.
rule onlyOwnerCanGrantOperatorship(env e, method f, calldataarg args, address account, address operator) 
filtered {
  f -> !isHelperMethod(f)  
} {
    requireClearExecutionContext();
    // msg.sender is not owner
    require(e.msg.sender != account);
    require(!haveCommonOwner(account, e.msg.sender));

    bool isOperatorBefore = isAccountOperator(account, operator);
    f(e, args);
    bool isOperatorAfter = isAccountOperator(account, operator);

    assert isOperatorAfter == isOperatorBefore;
}

/// 3. An Account can have multiple Account Operators.
/// Base case: An account can enable an operator
rule accountCanHaveMultipleOperators_baseCase(env e, method f, calldataarg args, address account, address operator) {
    requireClearExecutionContext();
    require(!isAccountOperator(account, operator));

    setAccountOperator(e, args);

    satisfy isAccountOperator(account, operator);
}

/// 3. An Account can have multiple Account Operators.
/// Inductive case: An account can have more than one operator
rule accountCanHaveMultipleOperators_inductiveCase(env e, method f, calldataarg args, address account, address operator1, address operator2) {
    requireClearExecutionContext();
    require(isAccountOperator(account, operator1));

    bool isNewOperatorBefore = isAccountOperator(account, operator2);
    setAccountOperator(e, args);
    bool isNewOperatorAfter = isAccountOperator(account, operator2);

    satisfy isNewOperatorAfter && !isNewOperatorBefore;
}

/// 4.1 Each Account can have at most 20 Collateral Vaults enabled at a time
/// Base case: An account can enable a collateral vault
rule accountCanHaveAtMost20Collaterals_baseCase(env e, method f, calldataarg args, address account) 
filtered {
  f -> !isHelperMethod(f)  
} {
    requireClearExecutionContext();

    uint256 collateralsBefore = numAccountCollaterals(account);
    require(numAccountCollaterals(account) == 0);

    enableCollateral(e, args);

    satisfy numAccountCollaterals(account) == 1;
}

/// 4.2 Each Account can have at most 20 Collateral Vaults enabled at a time
/// Inductive case: An account can enable more than one collateral vault
rule accountCanHaveAtMost20Collaterals_inductiveCase(env e, method f, calldataarg args, address account) 
filtered {
  f -> !isHelperMethod(f)  
} {
    requireClearExecutionContext();

    mathint collateralsBefore = numAccountCollaterals(account);
    require(collateralsBefore > 0);

    enableCollateral(e, args);

    mathint collateralsAfter = numAccountCollaterals(account);
    satisfy collateralsAfter == collateralsBefore + 1;
}

/// 4.3 Each Account can have at most 20 Collateral Vaults enabled at a time
/// Boundary: An account cannot enable more than 20 collateral vaults
rule accountCanHaveAtMost20Collaterals(env e, method f, calldataarg args, address account) 
filtered {
  f -> !isHelperMethod(f)  
} {
    requireClearExecutionContext();
    require(numAccountCollaterals(account) == 20);

    f(e, args);

    assert numAccountCollaterals(account) <= 20;
}

// 5. An account can only have one controller
rule controllersAreZeroOrOne(env e, method f, calldataarg args, address account) 
filtered {
  f -> !isHelperMethod(f)  
} {
    requireClearExecutionContext();

    require(numAccountControllers(account) <= 1);

    f(e, args);

    assert numAccountControllers(account) <= 1;
}

/// 6. (part) Only an Account Owner can grant permission to an Account Operator to operate on behalf of the Account.
rule onlyOwnerOrOperatorCanMutateCollateralVaultSet(env e, method f, calldataarg args, address account) 
filtered {
  f -> !isHelperMethod(f)  
} {
    requireClearExecutionContext();
    // msg.sender is not owner
    require(e.msg.sender != account);
    require(!haveCommonOwner(account, e.msg.sender));
    
    // msg.sender is not an operator
    require(!isAccountOperator(account, e.msg.sender));

    uint8 collateralsBefore = numAccountCollaterals(account);
    f(e, args);
    uint8 collateralsAfter = numAccountCollaterals(account);

    assert collateralsBefore == collateralsAfter;
}

/// 7. Only an Account Owner or the Account Operator can enable a Controller Vault for the Account.
rule onlyOwnerOrOperatorCanEnableCollateralVault(
    env e, 
    method f, 
    calldataarg args, 
    address account, 
    address vault
) filtered {
  f -> !isHelperMethod(f)  
} {
    requireClearExecutionContext();
    // msg.sender is not owner
    require(e.msg.sender != account);
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
rule onlyControllerVaultCanDisableItself(env e, method f, calldataarg args, address account, address vault) 
filtered {
  f -> !isHelperMethod(f)  
} {
    requireClearExecutionContext();
    // msg.sender is not controller for account
    require(!isControllerEnabled(account, e.msg.sender));
    // vault is controller for account
    require(isControllerEnabled(account, vault));

    f(e, args);

    // vault is still controller for account
    assert isControllerEnabled(account, vault);
}
