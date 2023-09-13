methods {
    // CVC envfree methods
    function name() external returns (string memory) envfree;
    function version() external returns (string memory) envfree;
    function OPERATOR_PERMIT_TYPEHASH() external returns (bytes32) envfree => CONSTANT;
    function getExecutionContext(
        address controllerToCheck
    )
        external
        returns (ICVC.ExecutionContext memory, bool)
        envfree;
    function getPrefix(address account) external returns(uint152) envfree;
    function getAccountOwner(
        address account
    ) external returns (address) envfree;
    function getAccountOperatorAuthExpiryTimestamp(
        address account,
        address operator
    ) external returns (uint40) envfree;
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
    function isAccountStatusCheckDeferred(
        address account
    ) external returns (bool) envfree;
    function isVaultStatusCheckDeferred(
        address vault
    ) external returns (bool) envfree;

    // Harness helper methods
    function numAccountCollaterals(address account) external returns (uint8) envfree;
    function numAccountControllers(address account) external returns (uint8) envfree;
    function getOwnerLookup(uint152 prefix) external returns (address) envfree;
    function getExecutionContextChecksLock() external returns (bool) envfree;
    function getExecutionContextImpersonateLock() external returns (bool) envfree;
    function getExecutionContextBatchDepth() external returns (uint8) envfree;
    function getExecutionContextOnBehalfOfAccount() external returns (address) envfree;
    function getExecutionContextStamp() external returns (uint72) envfree;
    function getAccountStatusChecksSize() external returns (uint8) envfree;
    function getVaultStatusChecksSize() external returns (uint8) envfree;
}

definition isExcludedMethod(method f) returns bool = 
    f.isView || f.isPure || f.selector == 0xc16ae7a4; // Exclude batch method

definition isAccountCheckInsertingMethod(method f) returns bool = 
    f.selector == sig:requireAccountStatusCheck(address).selector    
    || f.selector == sig:requireAccountsStatusCheck(address[] calldata).selector    
    || f.selector == sig:requireAccountAndVaultStatusCheck(address).selector;

definition isVaultCheckInsertingMethod(method f) returns bool = 
    f.selector == sig:requireVaultStatusCheck().selector    
    || f.selector == sig:requireAccountAndVaultStatusCheck(address).selector;

/// Used to eliminate false positives due to starting from an unreachable state
function requireClearExecutionContext() {
  require getExecutionContextChecksLock() == false
    && getExecutionContextImpersonateLock() == false
    && getExecutionContextBatchDepth() == 0 
    && getExecutionContextOnBehalfOfAccount() == 0 
    && getAccountStatusChecksSize() == 0 
    && getVaultStatusChecksSize() == 0;
}

/// After a call the execution context is zeroed out
/// If this invariant fails, assume all rules with `requireClearExecutionContext` fail
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
  f -> !isExcludedMethod(f)  
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
  f -> !isExcludedMethod(f)  
} {
    requireClearExecutionContext();
    // msg.sender is not owner
    require(e.msg.sender != account);
    require(!haveCommonOwner(e, account, e.msg.sender));
    require(!isAccountOperator(e, account, operator));

    f(e, args);

    assert !isAccountOperator(e, account, operator);
}

/// 3. An Account can have multiple Account Operators.
/// Base case: An account can enable an operator
rule accountCanHaveMultipleOperators_baseCase(env e, method f, calldataarg args, address account, address operator) {
    requireClearExecutionContext();
    require(!isAccountOperator(e, account, operator));

    setAccountOperator(e, args);

    satisfy isAccountOperator(e, account, operator);
}

/// 3. An Account can have multiple Account Operators.
/// Inductive case: An account can have more than one operator
rule accountCanHaveMultipleOperators_inductiveCase(env e, method f, calldataarg args, address account, address operator1, address operator2) {
    requireClearExecutionContext();
    require(isAccountOperator(e, account, operator1));

    bool isNewOperatorBefore = isAccountOperator(e, account, operator2);
    setAccountOperator(e, args);
    bool isNewOperatorAfter = isAccountOperator(e, account, operator2);

    satisfy isNewOperatorAfter && !isNewOperatorBefore;
}

/// 4.1 Each Account can have at most 20 Collateral Vaults enabled at a time
/// Base case: An account can enable a collateral vault
rule accountCanHaveAtMost20Collaterals_baseCase(env e, method f, calldataarg args, address account) 
filtered {
  f -> !isExcludedMethod(f)  
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
  f -> !isExcludedMethod(f)  
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
  f -> !isExcludedMethod(f)  
} {
    requireClearExecutionContext();
    require(numAccountCollaterals(account) == 20);

    f(e, args);

    assert numAccountCollaterals(account) <= 20;
}

// 5. An account can only have one controller
rule controllersAreZeroOrOne(env e, method f, calldataarg args, address account) 
filtered {
  f -> !isExcludedMethod(f)  
} {
    requireClearExecutionContext();

    require(numAccountControllers(account) <= 1);

    f(e, args);

    assert numAccountControllers(account) <= 1;
}

/// 6. (part) Only an Account Owner can grant permission to an Account Operator to operate on behalf of the Account.
rule onlyOwnerOrOperatorCanMutateCollateralVaultSet(env e, method f, calldataarg args, address account) 
filtered {
  f -> !isExcludedMethod(f)  
} {
    requireClearExecutionContext();
    // msg.sender is not owner
    require(e.msg.sender != account);
    require(!haveCommonOwner(e, account, e.msg.sender));
    
    // msg.sender is not an operator
    require(!isAccountOperator(e, account, e.msg.sender));

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
  f -> !isExcludedMethod(f)  
} {
    requireClearExecutionContext();
    // msg.sender is not owner
    require(e.msg.sender != account);
    require(!haveCommonOwner(e, account, e.msg.sender));
    
    // msg.sender is not an operator
    require(!isAccountOperator(e, account, e.msg.sender));

    // vault is not enabled
    require(!isControllerEnabled(account, vault));

    f(e, args);

    // vault is still not enabled
    assert !isControllerEnabled(account, vault);
}

/// 8. Only a Controller Vault can disable itself for the Account.
rule onlyControllerVaultCanDisableItself(env e, method f, calldataarg args, address account, address vault) 
filtered {
  f -> !isExcludedMethod(f)  
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

/// 10. Only an Owner or the Operator of the specified Account can call other contract through the CVC.
rule onlyOwnerOrOperatorCanCallExternalContract(env e, address targetContract, address account, bytes data) {
    requireClearExecutionContext();
    require(account != 0);

    bool isOwnerOrOperator = e.msg.sender == account || haveCommonOwner(e, account, e.msg.sender) || isAccountOperator(e, account, e.msg.sender);

    call@withrevert(e, targetContract, account, data);

    // If call was successful then caller must have been owner or operator
    assert !lastReverted => isOwnerOrOperator;
}

/// 11. If there's only one enabled Controller Vault for an Account, only that Controller can impersonate the Account's call into any of its enabled Collateral Vaults.
rule onlyOwnerOrSoleControllerCanImpersonateAccount(env e, address targetContract, address account, bytes data) {
    requireClearExecutionContext();
    require(account != 0);
    bool isOwnerOrSoleController = e.msg.sender == account || haveCommonOwner(e, account, e.msg.sender) || numAccountControllers(account) == 1 && isControllerEnabled(account, e.msg.sender);

    impersonate@withrevert(e, targetContract, account, data);

    // If impersonate was successful then caller must have been a sole controller
    assert !lastReverted => isOwnerOrSoleController;
}

/// 13.2 Batches can be nested up to 10 levels deep.
/// Inductive case: Batch depth can be more than 1;
rule batchesCanBeNested(env e, calldataarg args) {
    require(getExecutionContextBatchDepth() == 1);

    batch(e, args); 

    assert getExecutionContextBatchDepth() == 1;
}


/// 13.2 Batches can be nested up to 10 levels deep.
/// Inductive case: Batch depth can be more than 1;
rule batchesCanBeNestedMoreThanOneLevel(env e, calldataarg args) {
    require(getExecutionContextBatchDepth() == 8);

    batch(e, args); 

    satisfy getExecutionContextBatchDepth() == 8;
}

/// 13.3 Batches can be nested up to 10 levels deep.
/// Boundary case: Batch depth cannot exceed 10 levels;
rule batchesCanBeNestedUpTo10Levels(env e, calldataarg args) {
    require(getExecutionContextBatchDepth() == 9);

    batch@withrevert(e, args); 

    assert lastReverted;
}

/// 15. CVC defers Account Status Checks and Vault Status Checks until the end of the transaction only if the operation requiring them is part of a batch. Otherwise they must be executed immediately.
rule onlyBatchCanDeferChecks(env e, method f, calldataarg args) 
filtered {
    f -> !isExcludedMethod(f)
} {
    requireClearExecutionContext();
    f(e, args);

    assert getAccountStatusChecksSize() == 0 && getVaultStatusChecksSize() == 0;
}

/// 16.1 Account Status Checks can be deferred for at most 20 Accounts at a time.
/// Base case: Batch can defer 1 Account Status Check
rule batchCanDeferOneAccountCheck(env e, method f, calldataarg args) 
filtered {
    f -> isAccountCheckInsertingMethod(f)
} {
    require(getExecutionContextBatchDepth() > 0);
    require(getAccountStatusChecksSize() == 0);
    f(e, args);

    satisfy getAccountStatusChecksSize() == 1;
}

/// 16.2 Account Status Checks can be deferred for at most 20 Accounts at a time.
/// Inductive case: Batch can defer more than 1 Account Status Check
rule batchCanDefer20AccountChecks(env e, method f, calldataarg args) 
filtered {
    f -> isAccountCheckInsertingMethod(f)
} {
    require(getExecutionContextBatchDepth() > 0);
    require(getAccountStatusChecksSize() == 1);
    f(e, args);

    satisfy getAccountStatusChecksSize() == 2;
}

/// 16.3 Account Status Checks can be deferred for at most 20 Accounts at a time.
/// Boundary case: Batch cannot defer more than 20 Account Status Checks
rule batchCannotDeferMoreThan20AccountChecks(env e, method f, calldataarg args) 
filtered {
    f -> isAccountCheckInsertingMethod(f)
} {
    require(getExecutionContextBatchDepth() == 20);
    require(getAccountStatusChecksSize() == 20);
    f(e, args);

    assert getAccountStatusChecksSize() <= 20;
}

/// 17.1 Vault Status Checks can be deferred for at most 20 Accounts at a time.
/// Base case: Batch can defer 1 Vault Status Check
rule batchCanDeferOneVaultCheck(env e, method f, calldataarg args) 
filtered {
    f -> isVaultCheckInsertingMethod(f)
} {
    require(getExecutionContextBatchDepth() > 0);
    require(getVaultStatusChecksSize() == 0);
    f(e, args);

    satisfy getVaultStatusChecksSize() == 1;
}

/// 17.2 Vault Status Checks can be deferred for at most 20 Accounts at a time.
/// Inductive case: Batch can defer more than 1 Vault Account Status Check
rule batchCanDefer20VaultChecks(env e, method f, calldataarg args) 
filtered {
    f -> isVaultCheckInsertingMethod(f)
} {
    require(getExecutionContextBatchDepth() > 0);
    require(getVaultStatusChecksSize() == 1);
    f(e, args);

    satisfy getVaultStatusChecksSize() == 2;
}

/// 17.3 Vault Status Checks can be deferred for at most 20 Accounts at a time.
/// Boundary case: Batch can defer Vault Account Status Check
rule batchCannotDeferMoreThan20VaultChecks(env e, method f, calldataarg args) 
filtered {
    f -> isVaultCheckInsertingMethod(f)
} {
    require(getVaultStatusChecksSize() <= 20);
    f(e, args);

    assert getVaultStatusChecksSize() <= 20;
}

/// 19. If there's only one enabled Controller Vault for an Account, CVC allows currently enabled Controller to forgive the Account Status Check if it's deferred.
rule onlySoleControllerCanForgiveAccountCheck(env e, calldataarg args, address account, address checked) {
    // Caller is sole controller
    require(numAccountControllers(account) == 1);
    require(isControllerEnabled(account, e.msg.sender));
    require(isAccountStatusCheckDeferred(checked));

    forgiveAccountsStatusCheck(e, args);

    satisfy !isAccountStatusCheckDeferred(checked);
}

/// 20. CVC allows a Vault to forgive the Vault Status Check for itself if it's deferred.
rule vaultCanForgiveStatusCheckForItself(env e, calldataarg args, address account) {
    // Caller is controller
    require(isControllerEnabled(account, e.msg.sender));
    require(isVaultStatusCheckDeferred(e.msg.sender));

    forgiveVaultStatusCheck(e, args);

    satisfy !isVaultStatusCheckDeferred(e.msg.sender);
}

// 21. Simulation functions must not modify the state.
rule batchSimulationDoesNotModifyState(env e, calldataarg args) {
    requireClearExecutionContext();

    storage initialStorage = lastStorage;
    batchSimulation(e, args);
    storage nextStorage = lastStorage;

    assert initialStorage[currentContract] == nextStorage[currentContract];
}