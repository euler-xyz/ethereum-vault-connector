// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./Set.sol";
import "./interfaces/ICreditVaultConnector.sol";

abstract contract TransientStorage {
    enum SetType {
        Account,
        Vault
    }

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
