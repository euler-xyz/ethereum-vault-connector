// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Set.sol";
import "../src/Types.sol";

contract SetTest is Test {
    using Set for Types.SetStorage;
    Types.SetStorage setStorage;
    uint counter;

    function test_InsertRemove(address[] memory elements, uint64 seed) public {
        // ------------------ INSERTING ------------------
        // make the first two elements identical to exercise an edge case
        if (++counter % 10 == 0 && elements.length >= 2) {
            elements[0] = elements[1];
        }

        // count added elements not to exceed the limit
        uint expectedNumElements;
        for (uint i = 0; i < elements.length && expectedNumElements < 20; ++i) {
            if (setStorage.insert(elements[i])) ++expectedNumElements;
        }
        
        // check the number of elements
        address[] memory array = setStorage.get();
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
        while(setStorage.get().length > 0) {
            uint lengthBeforeRemoval = setStorage.get().length;
            uint indexToBeRemoved = seed % lengthBeforeRemoval;
            address elementToBeRemoved = setStorage.get()[indexToBeRemoved];

            // try to remove non-existent element to exercise an edge case
            if (++cnt % 5 == 0) {
                address candidate = address(uint160(cnt));

                if (!setStorage.contains(candidate)) {
                    assertEq(setStorage.remove(candidate), false);
                    assertEq(setStorage.get().length, lengthBeforeRemoval);
                }
            } else {
                assertEq(setStorage.contains(elementToBeRemoved), true);
                assertEq(setStorage.remove(elementToBeRemoved), true);
                assertEq(setStorage.get().length, lengthBeforeRemoval - 1);
            }
        }
    }

    function test_InsertRevertIfTooManyElements() public {
        for (uint i = 0; i < 20; ++i) {
            assertEq(setStorage.insert(address(uint160(i))), true);
        }

        vm.expectRevert(Set.TooManyElements.selector);
        setStorage.insert(address(uint160(100)));
    }
}
