// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

abstract contract Constants {
    // Protocol parameters

    uint internal constant MAX_SUBACCOUNT_ELEMENTS = 20; // per sub-account
    uint internal constant MAX_POSSIBLE_ELEMENTS = 2**8; // limited by size of ArrayStorage.numElements
    uint internal constant COLLATERAL_ARRAY_TYPE = 0;
    uint internal constant LIABILITY_ARRAY_TYPE = 1;
    uint internal constant LIQUIDITY_DEFERRAL_ARRAY_TYPE = 0;
    uint internal constant OPERATED_MARKETS_ARRAY_TYPE = 1;

    // Reentrancy bitmask

    uint internal constant REENTRANCYLOCK__INIT_STATE = 1 << 0;
    uint internal constant REENTRANCYLOCK__LOCK = 1 << 1;
    uint internal constant REENTRANCYLOCK__DEFERRAL = 1 << 2;
    uint internal constant REENTRANCYLOCK__IN_LIQUIDITY_CHECK = 1 << 3;
    uint internal constant REENTRANCYLOCK__IN_MARKET_STATUS_CHECK = 1 << 4;


    // Hooks

    uint8 internal constant HOOK__MARKET_LOAD_CACHE = 0;
    uint8 internal constant HOOK__MARKET_END_OF_TX = 1;


    // Pause bitmask

    uint8 internal constant PAUSE__COMPLETE = 1 << 0;
    uint8 internal constant PAUSE__DEPOSIT  = 1 << 1;
    uint8 internal constant PAUSE__WITHDRAW = 1 << 2;
    uint8 internal constant PAUSE__BORROW   = 1 << 3;
    uint8 internal constant PAUSE__REPAY    = 1 << 4;
    uint8 internal constant PAUSE__MINT     = 1 << 5;
    uint8 internal constant PAUSE__BURN     = 1 << 6;


    // Modules

    uint internal constant MODULEID__INSTALLER = 1;
    uint internal constant MODULEID__GOVERNANCE = 2;
    uint internal constant MODULEID__MARKETS = 3;
    uint internal constant MODULEID__EXEC = 4;
}
