// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

abstract contract Types {
    struct ExecutionContext {
        uint8 batchDepth;
        bool checksInProgressLock;
        address onBehalfOfAccount;
    }

    struct SetStorage {
        uint8 numElements;
        address firstElement;
        address[2**8] elements;
    }

    struct BatchItem {
        bool allowError;
        address onBehalfOfAccount;
        address targetContract;
        uint msgValue;
        bytes data;
    }

    struct BatchResult {
        bool success;
        bytes result;
    }
}
