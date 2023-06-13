// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./Types.sol";

library Array {
    uint internal constant MAX_PRESENT_ELEMENTS = 20;

    function doAddElement(Types.ArrayStorage storage arrayStorage, address element) internal returns (bool wasAdded) {
        address firstElement = arrayStorage.firstElement;
        uint8 numElements = arrayStorage.numElements;

        if (numElements != 0) {
            if (firstElement == element) return false;
            for (uint i = 1; i < numElements;) {
                if (arrayStorage.elements[i] == element) return false;
                unchecked { ++i; }
            }
        }

        require(numElements < MAX_PRESENT_ELEMENTS, "e/array/too-many-elements");

        if (numElements == 0) arrayStorage.firstElement = element;
        else arrayStorage.elements[numElements] = element;

        arrayStorage.numElements = numElements + 1;

        return true;
    }

    function doRemoveElement(Types.ArrayStorage storage arrayStorage, address element) internal returns (bool wasRemoved) {
        address firstElement = arrayStorage.firstElement;
        uint8 numElements = arrayStorage.numElements;
        uint searchIndex = type(uint).max;

        if (numElements == 0) return false;

        if (firstElement == element) {
            searchIndex = 0;
        } else {
            for (uint i = 1; i < numElements;) {
                if (arrayStorage.elements[i] == element) {
                    searchIndex = i;
                    break;
                }
                unchecked { ++i; }
            }

            if (searchIndex == type(uint).max) return false;
        }

        uint lastMarketIndex;
        unchecked { lastMarketIndex = numElements - 1; }

        if (searchIndex != lastMarketIndex) {
            if (searchIndex == 0) arrayStorage.firstElement = arrayStorage.elements[lastMarketIndex];
            else arrayStorage.elements[searchIndex] = arrayStorage.elements[lastMarketIndex];
        }

        arrayStorage.numElements = uint8(lastMarketIndex);

        if (lastMarketIndex != 0) delete arrayStorage.elements[lastMarketIndex];

        return true;
    }

    function getArray(Types.ArrayStorage storage arrayStorage) internal view returns (address[] memory) {
        address firstElement = arrayStorage.firstElement;
        uint8 numElements = arrayStorage.numElements;

        address[] memory output = new address[](numElements);
        if (numElements == 0) return output;

        output[0] = firstElement;

        for (uint i = 1; i < numElements;) {
            output[i] = arrayStorage.elements[i];
            unchecked { ++i; }
        }

        return output;
    }

    function arrayIncludes(Types.ArrayStorage storage arrayStorage, address element) internal view returns (bool) {
        address firstElement = arrayStorage.firstElement;
        uint8 numElements = arrayStorage.numElements;

        if (numElements == 0) return false;
        if (firstElement == element) return true;

        for (uint i = 1; i < numElements;) {
            if (arrayStorage.elements[i] == element) return true;
            unchecked { ++i; }
        }

        return false;
    }
}
