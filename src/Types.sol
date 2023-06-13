// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

abstract contract Types {
    uint internal constant MAX_POSSIBLE_ELEMENTS = 2**8;
    uint internal constant MAX_PRESENT_ELEMENTS = 20;

    struct AddressStorage {
        bool isActiveMarket;
        bool useAccountOperatorController;
        address accountOperatorOrController;
    }

    struct ArrayStorage {
        address firstElement;
        uint8 numElements;
        address[MAX_POSSIBLE_ELEMENTS] elements;
    }

    struct EulerBatchItem {
        bool allowError;
        address targetAccount;
        address targetContract;
        uint msgValue;
        bytes data;
    }

    struct EulerBatch {
        bool isSimulation;
        bytes32 referralCode;
        EulerBatchItem[] items;
    }

    struct EulerBatchItemSimulationResult {
        bool success;
        bytes result;
    }
}
