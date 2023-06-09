// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

abstract contract Constants {
    uint internal constant MAX_SUBACCOUNT_ELEMENTS = 20; // per sub-account
    uint internal constant MAX_POSSIBLE_ELEMENTS = 2**8; // limited by size of ArrayStorage.numElements

    uint internal constant COLLATERAL_ARRAY_TYPE = 0;
    uint internal constant LIABILITY_ARRAY_TYPE = 1;

    uint internal constant LIQUIDITY_DEFERRAL_ARRAY_TYPE = 0;
    uint internal constant MARKET_STATUS_ARRAY_TYPE = 1;

    uint internal constant HOOK__MARKET_FIRST_CALL = 0;
    uint internal constant HOOK__MARKET_END_OF_TX = 1;
}
