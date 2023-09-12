methods {
    // CVC harnessed delegatecall
    function harness_delegatecall() 
        internal 
        returns(bool) 
        with(env e) 
        => simulateSelfDelegatecall(e);

    // CVC envfree methods
    function name() external returns (string memory) envfree;
    function version() external returns (string memory) envfree;
    function OPERATOR_PERMIT_TYPEHASH() external returns (bytes32) envfree;
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

definition isHelperMethod(method f) returns bool = f.isView || f.isPure;
    // f.selector == sig:numAccountCollaterals(address).selector
    // || f.selector == sig:numAccountControllers(address).selector
    // || f.selector == sig:getOwnerLookup(uint152).selector
    // || f.selector == sig:getExecutionContextChecksLock().selector
    // || f.selector == sig:getExecutionContextImpersonateLock().selector
    // || f.selector == sig:getExecutionContextBatchDepth().selector
    // || f.selector == sig:getExecutionContextOnBehalfOfAccount().selector
    // || f.selector == sig:getExecutionContextStamp().selector
    // || f.selector == sig:getAccountStatusChecksSize().selector
    // || f.selector == sig:getVaultStatusChecksSize().selector
    // || f.selector == sig:isAccountOperator(address, address).selector;


function simulateSelfDelegatecall(env e) returns bool {
    // Replicate delegatecall semantics
    env e2;
    require(
        e2.block.number == e.block.number
        && e2.block.timestamp == e.block.timestamp
        && e2.tx.origin == e.tx.origin
        && e2.msg.value == e.msg.value
        && e2.msg.sender == currentContract
    );

    calldataarg args;

    // CVL does not support parametric methods in CVL functions, so we must implement a call table
    mathint rand;
    mathint idx = rand % 29;

    // Not implemented with else-if blocks for easier analysis on the prover UI
    // Otherwise we need to manually expand the section for every else-if
    if (idx == 0) { invalidateAllPermits@withrevert(e2, args); } 
    if (idx == 1) { invalidateAccountOperatorPermits@withrevert(e2, args); } 
    if (idx == 2) { setAccountOperator@withrevert(e2, args); } 
    if (idx == 3) { setAccountOperator@withrevert(e2, args); } 
    if (idx == 4) { setAccountOperatorPermitECDSA@withrevert(e2, args); } 
    if (idx == 5) { setAccountOperatorPermitERC1271@withrevert(e2, args); } 
    if (idx == 6) { enableCollateral@withrevert(e2, args); } 
    if (idx == 7) { disableCollateral@withrevert(e2, args); } 
    if (idx == 8) { enableController@withrevert(e2, args); } 
    if (idx == 9) { disableController@withrevert(e2, args); } 
    if (idx == 10) { call@withrevert(e2, args); } 
    if (idx == 11) { impersonate@withrevert(e2, args); } 
    if (idx == 12) { batch@withrevert(e2, args); } 
    if (idx == 13) { batchRevert@withrevert(e2, args); } 
    if (idx == 14) { batchSimulation@withrevert(e2, args); } 
    if (idx == 15) { checkAccountStatus@withrevert(e2, args); } 
    if (idx == 16) { checkAccountsStatus@withrevert(e2, args); } 
    if (idx == 17) { requireAccountStatusCheck@withrevert(e2, args); } 
    if (idx == 18) { requireAccountsStatusCheck@withrevert(e2, args); } 
    if (idx == 19) { requireAccountStatusCheckNow@withrevert(e2, args); } 
    if (idx == 20) { requireAccountsStatusCheckNow@withrevert(e2, args); } 
    if (idx == 21) { requireAllAccountsStatusCheckNow@withrevert(e2, args); } 
    if (idx == 22) { forgiveAccountStatusCheck@withrevert(e2, args); } 
    if (idx == 23) { requireVaultStatusCheck@withrevert(e2, args); } 
    if (idx == 24) { requireVaultStatusCheckNow@withrevert(e2, args); } 
    if (idx == 25) { requireVaultsStatusCheckNow@withrevert(e2, args); } 
    if (idx == 26) { requireAllVaultsStatusCheckNow@withrevert(e2, args);  } 
    if (idx == 27) { forgiveVaultStatusCheck@withrevert(e2, args); } 
    if (idx == 28) { requireAccountAndVaultStatusCheck@withrevert(e2, args);}
    // whew!

    return !lastReverted;
}

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

rule sanityCheckCVLDelegateCall(env e, calldataarg args, address account, address vault) {
    requireClearExecutionContext();

    require(!isControllerEnabled(account, vault));

    batch(e, args);
    // simulateSelfDelegatecall(e);
    // harness_delegatecall(e);

    satisfy isControllerEnabled(account, vault);
}

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
    require(!haveCommonOwner(e, account, e.msg.sender));

    bool isOperatorBefore = isAccountOperator(e, account, operator);
    f(e, args);
    bool isOperatorAfter = isAccountOperator(e, account, operator);

    assert isOperatorAfter == isOperatorBefore;
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
  f -> !isHelperMethod(f)  
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

/// 10. Only an Owner or the Operator of the specified Account can call other contract through the CVC.
// rule onlyOwnerOrOperatorCanCallExternalContract(env e, method f, calldataarg args, address account, address vault) 
// filtered {
//   f -> !isHelperMethod(f)  
// } {
//     requireClearExecutionContext();
//     // Called flag is false
//     require(!isCallableContractCalled);
//     // msg.sender is not controller for account
//     require(!isControllerEnabled(account, e.msg.sender));
//     // vault is controller for account
//     require(isControllerEnabled(account, vault));

//     f(e, args);

//     // vault is still controller for account
//     assert isControllerEnabled(account, vault);
// }

// 11. If there's only one enabled Controller Vault for an Account, only that Controller can impersonate the Account's call into any of its enabled Collateral Vaults.
// rule onlySoleControllerCanImpersonateAccount(env e, method f, calldataarg args, address account, address vault) 
// filtered {
//   f -> !isHelperMethod(f)  
// } {
//     requireClearExecutionContext();
// }

/// 13. Batches can be nested up to 10 levels deep.
ghost uint8 batchDepthReached;

hook Sstore currentContract.executionContext.batchDepth uint8 batchDepth STORAGE {
    if (batchDepth > batchDepthReached) {
        batchDepthReached = batchDepth;
    }
}

rule batchesCanBeNestedUpTo10Levels(env e, calldataarg args) {
    requireClearExecutionContext();
    batch(e, args);

    assert batchDepthReached < 10;
}

ghost uint8 numDeferredAccountChecks;

hook Sstore currentContract.accountStatusChecks.numElements uint8 numElements STORAGE {
    if (numElements > numDeferredAccountChecks) {
        numDeferredAccountChecks = numElements;
    }
}

ghost uint8 numDeferredVaultChecks;

hook Sstore currentContract.vaultStatusChecks.numElements uint8 numElements STORAGE {
    if (numElements > numDeferredVaultChecks) {
        numDeferredVaultChecks = numElements;
    }
}

/// 15. CVC defers Account Status Checks and Vault Status Checks until the end of the transaction only if the operation requiring them is part of a batch. Otherwise they must be executed immediately.
rule onlyBatchCanDeferChecks(env e, method f, calldataarg args) 
filtered {
    f -> f.selector != 0xc16ae7a4  
} {
    requireClearExecutionContext();
    f(e, args);

    assert numDeferredAccountChecks == 0 && numDeferredVaultChecks == 0;
}


/// 16. Account Status Checks can be deferred for at most 20 Accounts at a time.
rule batchCanDefer20AccountChecks(env e, calldataarg args) {
    requireClearExecutionContext();
    batch(e, args);

    satisfy numDeferredAccountChecks == 20;
}

rule batchCannotDeferMoreThan20AccountChecks(env e, calldataarg args) {
    requireClearExecutionContext();
    batch(e, args);

    assert numDeferredAccountChecks <= 20;
}

/// 17. Vault Status Checks can be deferred for at most 20 Accounts at a time.
rule batchCanDefer20VaultChecks(env e, calldataarg args) {
    requireClearExecutionContext();
    batch(e, args);

    satisfy numDeferredVaultChecks == 20;
}

rule batchCannotDeferMoreThan20VaultChecks(env e, calldataarg args) {
    requireClearExecutionContext();
    batch(e, args);

    assert numDeferredVaultChecks <= 20;
}

// 21. Simulation functions must not modify the state.
rule batchSimulationDoesNotModifyState(env e, calldataarg args) {
    requireClearExecutionContext();

    storage initialStorage = lastStorage;
    batchSimulation(e, args);
    storage nextStorage = lastStorage;

    assert initialStorage[currentContract] == nextStorage[currentContract];
}