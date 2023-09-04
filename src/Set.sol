// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

struct ElementStorage {
    uint8 stamp;
    address value;
}

struct SetStorage {
    uint8 stamp;
    uint8 numElements;
    address firstElement;
    ElementStorage[2 ** 8] elements;
}

library Set {
    error TooManyElements();

    uint public constant MAX_ELEMENTS = 20;

    /// @notice Inserts an element and returns whether the operation was successful or not.
    /// @param setStorage The set storage to which the element will be inserted.
    /// @param element The address of the element to be inserted.
    /// @return wasInserted A boolean value that indicates whether the element was inserted or not. If the element was already in the set storage, it returns false.
    function insert(
        SetStorage storage setStorage,
        address element
    ) internal returns (bool wasInserted) {
        uint numElements = setStorage.numElements;
        address firstElement = setStorage.firstElement;

        if (numElements != 0) {
            if (firstElement == element) return false;

            for (uint i = 1; i < numElements; ) {
                if (setStorage.elements[i].value == element) return false;

                unchecked {
                    ++i;
                }
            }
        }

        if (numElements >= MAX_ELEMENTS) revert TooManyElements();

        if (numElements == 0) {
            setStorage.firstElement = element;

            // gas optimization:
            // on the first element insertion, set the stamp to non-zero value
            // to keep the storage slot dirty when the element is removed
            setStorage.stamp = 1;
        } else {
            setStorage.elements[numElements].value = element;
        }

        unchecked {
            setStorage.numElements = uint8(numElements + 1);
        }

        return true;
    }

    /// @notice Removes an element and returns whether the operation was successful or not.
    /// @param setStorage The set storage from which the element will be removed.
    /// @param element The address of the element to be removed.
    /// @return wasRemoved A boolean value that indicates whether the element was removed or not. If the element was not in the set storage, it returns false.
    function remove(
        SetStorage storage setStorage,
        address element
    ) internal returns (bool wasRemoved) {
        uint numElements = setStorage.numElements;
        address firstElement = setStorage.firstElement;
        uint searchIndex = type(uint).max;

        if (numElements == 0) return false;

        if (firstElement == element) {
            searchIndex = 0;
        } else {
            for (uint i = 1; i < numElements; ) {
                if (setStorage.elements[i].value == element) {
                    searchIndex = i;
                    break;
                }
                unchecked {
                    ++i;
                }
            }

            if (searchIndex == type(uint).max) return false;
        }

        uint lastMarketIndex;
        unchecked {
            lastMarketIndex = numElements - 1;
        }

        if (searchIndex != lastMarketIndex) {
            if (searchIndex == 0) {
                setStorage.firstElement = setStorage
                    .elements[lastMarketIndex]
                    .value;
            } else {
                setStorage.elements[searchIndex].value = setStorage
                    .elements[lastMarketIndex]
                    .value;
            }
        }

        setStorage.numElements = uint8(lastMarketIndex);

        if (lastMarketIndex == 0) {
            delete setStorage.firstElement;
        } else {
            delete setStorage.elements[lastMarketIndex].value;
        }

        return true;
    }

    /// @notice Returns a copy of the set storage as a memory array.
    /// @dev The order of the elements in the memory array is not preserved.
    /// @param setStorage The set storage to be copied.
    /// @return A memory array that contains the same elements as the set storage.
    function get(
        SetStorage storage setStorage
    ) internal view returns (address[] memory) {
        uint numElements = setStorage.numElements;
        address firstElement = setStorage.firstElement;
        address[] memory output = new address[](numElements);

        if (numElements == 0) return output;

        output[0] = firstElement;

        for (uint i = 1; i < numElements; ) {
            output[i] = setStorage.elements[i].value;

            unchecked {
                ++i;
            }
        }

        return output;
    }

    /// @notice Checks if the set storage contains a given element and returns a boolean value that indicates the result.
    /// @param setStorage The set storage to be searched.
    /// @param element The address of the element to be checked.
    /// @return A boolean value that indicates whether the set storage includes the element or not.
    function contains(
        SetStorage storage setStorage,
        address element
    ) internal view returns (bool) {
        uint numElements = setStorage.numElements;
        address firstElement = setStorage.firstElement;

        if (numElements == 0) return false;
        if (firstElement == element) return true;

        for (uint i = 1; i < numElements; ) {
            if (setStorage.elements[i].value == element) return true;

            unchecked {
                ++i;
            }
        }

        return false;
    }
}
