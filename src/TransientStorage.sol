// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "./Set.sol";

abstract contract TransientStorage {
    enum SetType {
        Account,
        Vault
    }

    uint internal constant EC__BATCH_DEPTH_MASK =
        0x00000000000000000000000000000000000000000000000000000000000000FF;
    uint internal constant EC__CHECKS_LOCK_MASK =
        0x000000000000000000000000000000000000000000000000000000000000FF00;
    uint internal constant EC__IMPERSONATE_LOCK_MASK =
        0x0000000000000000000000000000000000000000000000000000000000FF0000;
    uint internal constant EC__ON_BEHALF_OF_ACCOUNT_MASK =
        0x000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000;
    uint internal constant EC__STAMP_MASK =
        0xFFFFFFFFFFFFFFFFFF0000000000000000000000000000000000000000000000;
    uint internal constant EC__ON_BEHALF_OF_ACCOUNT_OFFSET = 24;
    uint internal constant EC__STAMP_OFFSET = 184;
    uint internal constant EC__BATCH_DEPTH__INIT = 0;
    uint internal constant EC__BATCH_DEPTH__MAX = 9;
    uint internal constant EC__DUMMY_STAMP = 1;

    /// #if_updated "batch depth can only increase decrease by one" old(executionContext) & EC__BATCH_DEPTH_MASK != executionContext & EC__BATCH_DEPTH_MASK ==> ((old(executionContext) & EC__BATCH_DEPTH_MASK) + 1 == executionContext & EC__BATCH_DEPTH_MASK) || ((old(executionContext) & EC__BATCH_DEPTH_MASK) - 1 == executionContext & EC__BATCH_DEPTH_MASK);
    /// #if_updated "batch depth can only change if reentrancy locks are not acquired" old(executionContext) & EC__BATCH_DEPTH_MASK != executionContext & EC__BATCH_DEPTH_MASK ==> (old(executionContext) & EC__CHECKS_LOCK_MASK == 0) && (old(executionContext) & EC__IMPERSONATE_LOCK_MASK == 0);
    /// #if_updated "check lock can only change if impersonate lock is not acquired" old(executionContext) & EC__CHECKS_LOCK_MASK != executionContext & EC__CHECKS_LOCK_MASK ==> old(executionContext) & EC__IMPERSONATE_LOCK_MASK == 0;
    /// #if_updated "on behalf of account can only change if reentrancy locks are not acquired" old(executionContext) & EC__ON_BEHALF_OF_ACCOUNT_MASK != executionContext & EC__ON_BEHALF_OF_ACCOUNT_MASK ==> (old(executionContext) & EC__CHECKS_LOCK_MASK == 0) && (old(executionContext) & EC__IMPERSONATE_LOCK_MASK == 0);
    uint256 internal executionContext;
    SetStorage internal accountStatusChecks;
    SetStorage internal vaultStatusChecks;

    constructor() {
        // prepopulate the execution context storage slot to optimize gas consumption
        // (it should never be cleared again thanks to the stamp)
        executionContext = EC__DUMMY_STAMP << EC__STAMP_OFFSET;

        // prepopulate the status checks storage slots to optimize gas consumption
        // (it should be cheaper to insert the accounts and vaults addresses to be checked)
        accountStatusChecks.stamp = uint8(EC__DUMMY_STAMP);
        vaultStatusChecks.stamp = uint8(EC__DUMMY_STAMP);

        for (uint i = 1; i < Set.MAX_ELEMENTS; ) {
            accountStatusChecks.elements[i].stamp = uint8(EC__DUMMY_STAMP);
            vaultStatusChecks.elements[i].stamp = uint8(EC__DUMMY_STAMP);

            unchecked {
                ++i;
            }
        }
    }
}
