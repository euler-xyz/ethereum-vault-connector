// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Array.sol";
import "../src/Types.sol";

contract ArrayTest is Test {
    using Array for Types.ArrayStorage;
    Types.ArrayStorage arrayStorage;
    uint counter;

    function test_positive(address[] memory elements, uint64 seed) public {
        // ------------------ ADDING ------------------
        // make the first two elements identical to exercise an edge case
        if (++counter % 10 == 0 && elements.length >= 2) {
            elements[0] = elements[1];
        }

        // count added elements not to exceed the limit
        uint expectedNumElements;
        for (uint i = 0; i < elements.length && expectedNumElements < 20; ++i) {
            if (arrayStorage.doAddElement(elements[i])) ++expectedNumElements;
        }
        
        // check the number of elements
        address[] memory array = arrayStorage.getArray();
        assertEq(array.length, expectedNumElements);

        // check the elements
        uint lastExpectedIndex = 0;
        for (uint i = 0; i < array.length; ++i) {
            // expected element has to be found as the duplicates are not being inserted
            address expectedElement;
            uint seenBeforeCnt;

            do {
                seenBeforeCnt = 0;
                expectedElement = elements[lastExpectedIndex];
                
                for (uint j = 0; j < lastExpectedIndex; ++j) {
                    if (elements[lastExpectedIndex] == elements[j]) ++seenBeforeCnt;
                }
                
                ++lastExpectedIndex;
            } while (seenBeforeCnt != 0);

            assertEq(array[i], expectedElement);
        }

        // ------------------ REMOVING ------------------
        uint cnt;
        while(arrayStorage.getArray().length > 0) {
            uint lengthBeforeRemoval = arrayStorage.getArray().length;
            uint indexToBeRemoved = seed % lengthBeforeRemoval;
            address elementToBeRemoved = arrayStorage.getArray()[indexToBeRemoved];

            // try to remove non-existent element to exercise an edge case
            if (++cnt % 5 == 0) {
                address candidate = address(uint160(cnt));

                if (!arrayStorage.arrayIncludes(candidate)) {
                    assertEq(arrayStorage.doRemoveElement(candidate), false);
                    assertEq(arrayStorage.getArray().length, lengthBeforeRemoval);
                }
            } else {
                assertEq(arrayStorage.arrayIncludes(elementToBeRemoved), true);
                assertEq(arrayStorage.doRemoveElement(elementToBeRemoved), true);
                assertEq(arrayStorage.getArray().length, lengthBeforeRemoval - 1);
            }
        }
    }

    function test_negative() public {
        for (uint i = 0; i < 20; ++i) {
            assertEq(arrayStorage.doAddElement(address(uint160(i))), true);
        }

        vm.expectRevert("e/array/too-many-elements");
        arrayStorage.doAddElement(address(uint160(100)));
    }
}
