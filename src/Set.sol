// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

struct ElementStorage {
    address value;
    uint96 stamp;
}

struct SetStorage {
    uint8 numElements;
    address firstElement;
    uint88 stamp;
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
        address firstElement = setStorage.firstElement;
        uint numElements = setStorage.numElements;

        if (numElements == 0) {
            // gas optimization:
            // on the first element insertion, set the stamp to non-zero value
            // to keep the storage slot dirty when the element is removed
            setStorage.numElements = 1;
            setStorage.firstElement = element;
            setStorage.stamp = 1;
            return true;
        }

        if (firstElement == element) return false;

        for (uint i = 1; i < numElements; ) {
            if (setStorage.elements[i].value == element) return false;

            unchecked {
                ++i;
            }
        }

        if (numElements == MAX_ELEMENTS) revert TooManyElements();

        setStorage.elements[numElements].value = element;

        unchecked {
            setStorage.numElements = uint8(numElements + 1);
        }

        return true;
    }

    /// @notice Removes an element and returns whether the operation was successful or not.
    /// @param setStorage The set storage from which the element will be removed.
    /// @param element The address of the element to be removed.
    /// @return  A boolean value that indicates whether the element was removed or not. If the element was not in the set storage, it returns false.
    function remove(
        SetStorage storage setStorage,
        address element
    ) internal returns (bool) {
        address firstElement = setStorage.firstElement;
        uint numElements = setStorage.numElements;

        if (numElements == 0) return false;

        uint searchIndex;
        if (firstElement != element) {
            for (searchIndex = 1; searchIndex < numElements; ) {
                if (setStorage.elements[searchIndex].value == element) {
                    break;
                }
                unchecked {
                    ++searchIndex;
                }
            }

            if (searchIndex == numElements) return false;
        }

        if (numElements == 1) {
            setStorage.numElements = 0;
            setStorage.firstElement = address(0);
            setStorage.stamp = 1;
            return true;
        }

        uint lastIndex;
        unchecked {
            lastIndex = numElements - 1;
        }

        if (searchIndex != lastIndex) {
            if (searchIndex == 0) {
                setStorage.firstElement = setStorage.elements[lastIndex].value;
                setStorage.numElements = uint8(lastIndex);
            } else {
                setStorage.elements[searchIndex].value = setStorage
                    .elements[lastIndex]
                    .value;
                setStorage.numElements = uint8(lastIndex);
            }
        } else {
            setStorage.numElements = uint8(lastIndex);
        }

        delete setStorage.elements[lastIndex].value;

        return true;
    }

    /// @notice Returns a copy of the set storage as a memory array.
    /// @dev The order of the elements in the memory array is not preserved.
    /// @param setStorage The set storage to be copied.
    /// @return A memory array that contains the same elements as the set storage.
    function get(
        SetStorage storage setStorage
    ) internal view returns (address[] memory) {
        address firstElement = setStorage.firstElement;
        uint numElements = setStorage.numElements;
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
    /// @return found A boolean value that indicates whether the set storage includes the element or not.
    function contains(
        SetStorage storage setStorage,
        address element
    ) internal view returns (bool found) {
        address firstElement = setStorage.firstElement;
        uint numElements = setStorage.numElements;

        if (numElements == 0) return false;
        if (firstElement == element) return true;

        for (uint i = 1; i < numElements; ) {
            if (setStorage.elements[i].value == element) return true;

            unchecked {
                ++i;
            }
        }
    }

    /// @notice Iterates over each element in the set and applies the callback function to it.
    /// @dev The set is cleared as a result of this call.
    /// @param setStorage The set storage to be processed.
    /// @param callback The function to be applied to each element.
    function forEachAndClear(
        SetStorage storage setStorage,
        function(address) callback
    ) internal {
        uint numElements = setStorage.numElements;
        address firstElement = setStorage.firstElement;

        if (numElements == 0) return;

        setStorage.numElements = 0;

        for (uint i; i < numElements; ) {
            address element;
            if (i == 0) {
                element = firstElement;
                delete setStorage.firstElement;
            } else {
                element = setStorage.elements[i].value;
                delete setStorage.elements[i].value;
            }

            callback(element);

            unchecked {
                ++i;
            }
        }
    }

    /// @notice Iterates over each element in the set and applies the callback function to it, returning the array of callback results.
    /// @dev The set is cleared as a result of this call.
    /// @param setStorage The set storage to be processed.
    /// @param callback The function to be applied to each element.
    /// @return result An array of encoded bytes that are the results of the callback function.
    function forEachAndClearWithResult(
        SetStorage storage setStorage,
        function(address) returns (bool, bytes memory) callback
    ) internal returns (bytes[] memory) {
        uint numElements = setStorage.numElements;
        address firstElement = setStorage.firstElement;
        bytes[] memory result = new bytes[](numElements);

        if (numElements == 0) return result;

        setStorage.numElements = 0;

        for (uint i; i < numElements; ) {
            address element;
            if (i == 0) {
                element = firstElement;
                delete setStorage.firstElement;
            } else {
                element = setStorage.elements[i].value;
                delete setStorage.elements[i].value;
            }

            (bool result1, bytes memory result2) = callback(element);
            result[i] = abi.encode(result1, result2);

            unchecked {
                ++i;
            }
        }

        return result;
    }
}
