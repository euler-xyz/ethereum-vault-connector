// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

abstract contract Types {
    struct ExecutionContext {
        uint8 checksDeferredDepth;
        address onBehalfOfAccount;
    }

    struct SetStorage {
        uint8 numElements;
        address firstElement;
        address[2**8] elements;
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
