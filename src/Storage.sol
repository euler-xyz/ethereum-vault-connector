// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./Constants.sol";

abstract contract Storage is Constants {
    // Dispatcher and upgrades

    bool internal liquidityCheckDeferred;
    address internal governorAdmin;
    address internal eulerMarketRegistry;

    // Array Types

    struct ArrayStorage {
        address firstElement;
        uint8 numElements;
        address[MAX_POSSIBLE_ELEMENTS] elements;
    }

    // Account-level state

    mapping(address => address) internal accountOperators;   // account => operator
    mapping(address => ArrayStorage[2]) internal accountArrays;


    // Markets

    mapping(address => bool) internal isActive; // market => bool
    address[] internal activeMarkets;


    // Transient storage
    
    ArrayStorage[2] internal transientArrays;
    mapping(address => bytes) internal transientMapping;
}
