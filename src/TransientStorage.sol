// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "./ExecutionContext.sol";
import "./Set.sol";

/// @title TransientStorage
/// @author Euler Labs (https://www.eulerlabs.com/)
/// @notice This contract provides transient storage for the Credit Vault Connector.
/// @dev All the variables in this contract are considered transient meaning that their state does not change between transactions.
abstract contract TransientStorage {
    enum SetType {
        Account,
        Vault
    }

    EC internal executionContext;
    SetStorage internal accountStatusChecks;
    SetStorage internal vaultStatusChecks;

    constructor() {
        uint8 DUMMY_STAMP = 1;

        executionContext = ExecutionContext.initialize();

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
