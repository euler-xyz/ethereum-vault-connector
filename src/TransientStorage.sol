// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./Types.sol";

abstract contract TransientStorage is Types {
    bool internal checksDeferred;
    ArrayStorage internal accountStatusChecks;
    ArrayStorage internal vaultStatusChecks;
    mapping(address => bytes) internal vaultStatuses;
}
