// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./Set.sol";

abstract contract TransientStorage {
    enum SetType {
        Account,
        Vault
    }
    SetStorage internal accountStatusChecks;
    SetStorage internal vaultStatusChecks;
    address accountStatusCheckIgnoredFrom;
}
