// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./Types.sol";

abstract contract TransientStorage {
    enum SetType { Account, Vault }
    Types.SetStorage internal accountStatusChecks;
    Types.SetStorage internal vaultStatusChecks;
}
