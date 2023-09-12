// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "./Set.sol";
import "./interfaces/ICreditVaultConnector.sol";

abstract contract TransientStorage {
    enum SetType {
        Account,
        Vault
    }

    uint8 internal constant DUMMY_STAMP = 1;

    /// #if_updated "batch depth can only increase decrease by one" old(executionContext.batchDepth) != executionContext.batchDepth ==> old(executionContext.batchDepth) + 1 == executionContext.batchDepth || old(executionContext.batchDepth) - 1 == executionContext.batchDepth;
    /// #if_updated "batch depth can only change if reentrancy locks are not acquired" old(executionContext.batchDepth) != executionContext.batchDepth ==> !old(executionContext.checksLock) && !old(executionContext.impersonateLock);
    /// #if_updated "check lock can only change if impersonate lock is not acquired" old(executionContext.checksLock) != executionContext.checksLock ==> !old(executionContext.impersonateLock);
    /// #if_updated "on behalf of account can only change if reentrancy locks are not acquired" old(executionContext.onBehalfOfAccount) != executionContext.onBehalfOfAccount ==> !old(executionContext.checksLock) && !old(executionContext.impersonateLock);
    ICVC.ExecutionContext internal executionContext;
    SetStorage internal accountStatusChecks;
    SetStorage internal vaultStatusChecks;

    constructor() {
        // prepopulate the execution context storage slot to optimize gas consumption
        // (it should never be clear again thanks to the stamp)
        executionContext.stamp = DUMMY_STAMP;

        // prepopulate the status checks storage slots to optimize gas consumption
        // (it should be cheaper to insert the accounts and vaults addresses to be checked)
        accountStatusChecks.stamp = DUMMY_STAMP;
        vaultStatusChecks.stamp = DUMMY_STAMP;

        for (uint i = 1; i < Set.MAX_ELEMENTS; ) {
            accountStatusChecks.elements[i].stamp = DUMMY_STAMP;
            vaultStatusChecks.elements[i].stamp = DUMMY_STAMP;

            unchecked {
                ++i;
            }
        }
    }
}
