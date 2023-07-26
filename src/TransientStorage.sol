// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./Set.sol";

abstract contract TransientStorage {
    enum SetType {
        Account,
        Vault
    }

    constructor() {
        // set reserved field to 1 in order to optimize gas consumption 
        // (not to clear the storage slot when 0 elements in the set)
        accountStatusChecks.reserved = 1;
        vaultStatusChecks.reserved = 1;
    }

    SetStorage internal accountStatusChecks;
    SetStorage internal vaultStatusChecks;
}
