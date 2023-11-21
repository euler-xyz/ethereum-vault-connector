// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

/// @title ElementStorage
/// @notice This struct is used to store the value and stamp of an element.
/// @dev The stamp field is used to keep the storage slot non-zero when the element is removed.
/// @dev It allows for cheaper SSTORE when an element is inserted.
struct ElementStorage {
    /// @notice The value of the element.
    address value;
    /// @notice The stamp of the element.
    uint96 stamp;
}

/// @title SetStorage
/// @notice This struct is used to store the set data.
/// @dev To optimize the gas consuption, firstElement is stored in the same storage slot as the numElements
/// @dev so that for sets with one element, only one storage slot has to be read/written. To keep the elements
/// @dev array indexing consistent and because the first element is stored outside of the array, the elements[0]
/// @dev is not utilized. The stamp field is used to keep the storage slot non-zero when the element is removed.
/// @dev It allows for cheaper SSTORE when an element is inserted.
struct SetStorage {
    /// @notice The number of elements in the set.
    uint8 numElements;
    /// @notice The first element in the set.
    address firstElement;
    /// @notice The stamp of the set.
    uint88 stamp;
    /// @notice The array of elements in the set. Stores the elements starting from index 1.
    ElementStorage[2 ** 8] elements;
}

/// @title Set
/// @author Euler Labs (https://www.eulerlabs.com/)
/// @notice This library provides functions for managing sets of addresses.
/// @dev The maximum number of elements in the set is defined by the constant MAX_ELEMENTS.
library Set {
    error TooManyElements();

    uint8 public constant MAX_ELEMENTS = 20;
    uint8 internal constant EMPTY_ELEMENT_OFFSET = 1;
    uint8 internal constant DUMMY_STAMP = 1;

    /// @notice Initializes the set by setting the stamp field of the SetStorage and the stamp field of elements to
    /// DUMMY_STAMP.
    /// @dev The stamp field is used to keep the storage slot non-zero when the element is removed. It allows for
    /// cheaper SSTORE when an element is inserted.
    /// @param setStorage The set storage whose stamp fields will be initialized.
    function initialize(SetStorage storage setStorage) internal {
        setStorage.stamp = DUMMY_STAMP;

        for (uint256 i = EMPTY_ELEMENT_OFFSET; i < MAX_ELEMENTS;) {
            setStorage.elements[i].stamp = DUMMY_STAMP;

            unchecked {
                ++i;
            }
        }
    }

    /// @notice Inserts an element and returns information whether the element was inserted or not.
    /// @dev Reverts if the set is full but the element is not in the set storage.
    /// @param setStorage The set storage to which the element will be inserted.
    /// @param element The address of the element to be inserted.
    /// @return A boolean value that indicates whether the element was inserted or not. If the element was already in
    /// the set storage, it returns false.
    function insert(SetStorage storage setStorage, address element) internal returns (bool) {
        address firstElement = setStorage.firstElement;
        uint256 numElements = setStorage.numElements;

        if (numElements == 0) {
            // gas optimization:
            // on the first element insertion, set the stamp to non-zero value to keep the storage slot non-zero when
            // the element is removed. when a new element is inserted after the removal, it should be cheaper
            setStorage.numElements = 1;
            setStorage.firstElement = element;
            setStorage.stamp = DUMMY_STAMP;
            return true;
        }

        if (firstElement == element) return false;

        for (uint256 i = EMPTY_ELEMENT_OFFSET; i < numElements;) {
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

    /// @notice Removes an element and returns information whether the element was removed or not.
    /// @param setStorage The set storage from which the element will be removed.
    /// @param element The address of the element to be removed.
    /// @return A boolean value that indicates whether the element was removed or not. If the element was not in the set
    /// storage, it returns false.
    function remove(SetStorage storage setStorage, address element) internal returns (bool) {
        address firstElement = setStorage.firstElement;
        uint256 numElements = setStorage.numElements;

        if (numElements == 0) return false;

        uint256 searchIndex;
        if (firstElement != element) {
            for (searchIndex = EMPTY_ELEMENT_OFFSET; searchIndex < numElements;) {
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
            setStorage.stamp = DUMMY_STAMP;
            return true;
        }

        uint256 lastIndex;
        unchecked {
            lastIndex = numElements - 1;
        }

        if (searchIndex != lastIndex) {
            if (searchIndex == 0) {
                setStorage.firstElement = setStorage.elements[lastIndex].value;
                setStorage.numElements = uint8(lastIndex);
            } else {
                setStorage.elements[searchIndex].value = setStorage.elements[lastIndex].value;
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
    function get(SetStorage storage setStorage) internal view returns (address[] memory) {
        address firstElement = setStorage.firstElement;
        uint256 numElements = setStorage.numElements;
        address[] memory output = new address[](numElements);

        if (numElements == 0) return output;

        output[0] = firstElement;

        for (uint256 i = EMPTY_ELEMENT_OFFSET; i < numElements;) {
            output[i] = setStorage.elements[i].value;

            unchecked {
                ++i;
            }
        }

        return output;
    }

    /// @notice Checks if the set storage contains a given element and returns a boolean value that indicates the
    /// result.
    /// @param setStorage The set storage to be searched.
    /// @param element The address of the element to be checked.
    /// @return A boolean value that indicates whether the set storage includes the element or not.
    function contains(SetStorage storage setStorage, address element) internal view returns (bool) {
        address firstElement = setStorage.firstElement;
        uint256 numElements = setStorage.numElements;

        if (numElements == 0) return false;
        if (firstElement == element) return true;

        for (uint256 i = EMPTY_ELEMENT_OFFSET; i < numElements;) {
            if (setStorage.elements[i].value == element) return true;

            unchecked {
                ++i;
            }
        }

        return false;
    }

    /// @notice Iterates over each element in the set and applies the callback function to it.
    /// @dev The set is cleared as a result of this call.
    /// @param setStorage The set storage to be processed.
    /// @param callback The function to be applied to each element.
    function forEachAndClear(SetStorage storage setStorage, function(address) callback) internal {
        uint256 numElements = setStorage.numElements;
        address firstElement = setStorage.firstElement;

        if (numElements == 0) return;

        setStorage.numElements = 0;

        for (uint256 i; i < numElements;) {
            address element;
            if (i < EMPTY_ELEMENT_OFFSET) {
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

    /// @notice Iterates over each element in the set and applies the callback function to it, returning the array of
    /// callback results.
    /// @dev The set is cleared as a result of this call.
    /// @param setStorage The set storage to be processed.
    /// @param callback The function to be applied to each element.
    /// @return result An array of encoded bytes that are the addresses passed to the callback function and results of
    /// calling it.
    function forEachAndClearWithResult(
        SetStorage storage setStorage,
        function(address) returns (bool, bytes memory) callback
    ) internal returns (bytes[] memory) {
        uint256 numElements = setStorage.numElements;
        address firstElement = setStorage.firstElement;
        bytes[] memory results = new bytes[](numElements);

        if (numElements == 0) return results;

        setStorage.numElements = 0;

        for (uint256 i; i < numElements;) {
            address element;
            if (i < EMPTY_ELEMENT_OFFSET) {
                element = firstElement;
                delete setStorage.firstElement;
            } else {
                element = setStorage.elements[i].value;
                delete setStorage.elements[i].value;
            }

            (bool success, bytes memory result) = callback(element);
            results[i] = abi.encode(element, success, result);

            unchecked {
                ++i;
            }
        }

        return results;
    }
}
