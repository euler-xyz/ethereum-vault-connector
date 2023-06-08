// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./Constants.sol";

abstract contract Storage is Constants {
    // Dispatcher and upgrades

    uint internal reentrancyLock;

    address upgradeAdmin;
    address governorAdmin;
    address eulerFactory;

    mapping(uint => address) moduleLookup; // moduleId => module implementation
    mapping(uint => address) proxyLookup; // moduleId => proxy address

    struct TrustedSenderInfo {
        uint32 moduleId; // 0 = un-trusted
        address moduleImpl; // only non-zero for external single-proxy modules
    }

    mapping(address => TrustedSenderInfo) trustedSenders; // sender address => moduleId (0 = un-trusted)


    // Array Types

    struct ArrayStorage {
        address firstElement;
        uint8 numElements;
        address[MAX_POSSIBLE_ELEMENTS] elements;
    }

    // Account-level state
    // Sub-accounts are considered distinct accounts
    struct AccountStorage {
        // Packed slot:
        address operator;
        uint40 lastAccountUpdate;
    }

    mapping(address => AccountStorage) accountLookup;
    mapping(address => ArrayStorage[2]) internal accountArrays;


    // Markets

    struct MarketStorage {
        // Packed slot: 
        bool isRegistered;
        bool isActive;
        address marketGovernor;
        uint8 hookBitmask;
        uint8 pauseBitmask;
        uint64 reserved;
    }

    mapping(address => MarketStorage) internal marketLookup; // market => MarketStorage
    address[] internal activeMarkets;


    // Transient storage
    
    ArrayStorage[2] internal transientArrays;
}
