// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "./Set.sol";
import "./interfaces/ICreditVaultConnector.sol";

/// #if_succeeds "batch depth is in INIT state" executionContext.batchDepth == 0;
/// #if_succeeds "checks lock is false" !executionContext.checksLock;
/// #if_succeeds "impersonate lock is false" !executionContext.impersonateLock;
/// #if_succeeds "onBehalfOfAccount is zero address" executionContext.onBehalfOfAccount == address(0);
/// #if_succeeds "account status checks set is empty" accountStatusChecks.numElements == 0;
/// #if_succeeds "vault status checks set is empty" vaultStatusChecks.numElements == 0;
/// #invariant "account status checks set has at most 20 elements" accountStatusChecks.numElements <= 20;
/// #invariant "vault status checks set has at most 20 elements" vaultStatusChecks.numElements <= 20;
abstract contract TransientStorage {
    enum SetType {
        Account,
        Vault
    }

    /// #if_updated "batch depth can only increase decrease by one" old(executionContext.batchDepth) != executionContext.batchDepth ==> old(executionContext.batchDepth) + 1 == executionContext.batchDepth || old(executionContext.batchDepth) - 1 == executionContext.batchDepth;
    /// #if_updated "check lock must always change state 1" old(executionContext.checksLock) != executionContext.checksLock && old(executionContext.checksLock) ==> !executionContext.checksLock;
    /// #if_updated "check lock must always change state 2" old(executionContext.checksLock) != executionContext.checksLock && old(!executionContext.checksLock) ==> executionContext.checksLock;
    /// #if_updated "impersonate lock must always change state 1" old(executionContext.impersonateLock) != executionContext.impersonateLock && old(executionContext.impersonateLock) ==> !executionContext.impersonateLock;
    /// #if_updated "impersonate lock must always change state 2" old(executionContext.impersonateLock) != executionContext.impersonateLock && old(!executionContext.impersonateLock) ==> executionContext.impersonateLock;
    ICVC.ExecutionContext internal executionContext;
    SetStorage internal accountStatusChecks;
    SetStorage internal vaultStatusChecks;

    constructor() {
        // populate the storage slot so that:
        // - it's cheaper to set batchDepth from 0 to 1
        // - it's compatible with transient storage (EIP-1153)
        executionContext.reserved = 1;
    }
}
