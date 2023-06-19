// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./Types.sol";

library Array {
    error TooManyElements();

    uint internal constant MAX_PRESENT_ELEMENTS = 10;

    /// @notice Adds an element to the end of an array storage and returns whether the operation was successful or not. 
    /// @dev This function checks if the element is already in the array storage and if there is enough space to add it. 
    /// @param arrayStorage The array storage to which the element will be added. 
    /// @param element The address of the element to be added. 
    /// @return wasAdded A boolean value that indicates whether the element was added or not. If the element was already in the array storage, it returns false.
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

        if (numElements >= MAX_PRESENT_ELEMENTS) revert TooManyElements();

        if (numElements == 0) arrayStorage.firstElement = element;
        else arrayStorage.elements[numElements] = element;

        unchecked { arrayStorage.numElements = numElements + 1; }

        return true;
    }

    /// @notice Removes an element from an array storage and returns whether the operation was successful or not. 
    /// @dev This function checks if the element is in the array storage and if it is, it swaps it with the last element and then deletes the last element.  
    /// @param arrayStorage The array storage from which the element will be removed. 
    /// @param element The address of the element to be removed. 
    /// @return wasRemoved A boolean value that indicates whether the element was removed or not. If the element was not in the array storage, it returns false.
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

        if (lastMarketIndex == 0) delete arrayStorage.firstElement;
        else delete arrayStorage.elements[lastMarketIndex];

        return true;
    }

    /// @notice Returns a copy of an array storage as a memory array. 
    /// @param arrayStorage The array storage to be copied. 
    /// @return A memory array that contains the same elements as the array storage.
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

    /// @notice Checks if an array storage includes a given element and returns a boolean value that indicates the result. 
    /// @param arrayStorage The array storage to be searched. 
    /// @param element The address of the element to be checked. 
    /// @return A boolean value that indicates whether the array storage includes the element or not. 
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
