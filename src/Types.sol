// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

abstract contract Types {
    uint internal constant MAX_POSSIBLE_ELEMENTS = 2**8;

    struct ExecutionContext {
        uint8 checksDeferredState;
        address onBehalfOfAccount;
    }

    struct ArrayStorage {
        uint8 numElements;
        address firstElement;
        address[MAX_POSSIBLE_ELEMENTS] elements;
    }

    struct EulerBatchItem {
        bool allowError;
        address onBehalfOfAccount;
        address targetContract;
        uint msgValue;
        bytes data;
    }

    struct EulerResult {
        bool success;
        bytes result;
    }
}