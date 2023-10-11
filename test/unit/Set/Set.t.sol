// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../../src/Set.sol";

contract SetTest is Test {
    using Set for SetStorage;
    SetStorage setStorage;
    uint counter;

    function setUp() public {
        delete setStorage;
    }

    function test_InsertRemove(address[] memory elements, uint64 seed) public {
        // ------------------ SETUP ----------------------
        delete setStorage;

        // ------------------ INSERTING ------------------
        // make the first two elements identical to exercise an edge case
        if (++counter % 10 == 0 && elements.length >= 2) {
            elements[0] = elements[1];
        }

        // count added elements not to exceed the limit
        uint expectedNumElements;
        for (
            uint i = 0;
            i < elements.length && expectedNumElements < Set.MAX_ELEMENTS;
            ++i
        ) {
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
                    if (elements[lastExpectedIndex] == elements[j])
                        ++seenBeforeCnt;
                }

                ++lastExpectedIndex;
            } while (seenBeforeCnt != 0);

            assertEq(array[i], expectedElement);
        }

        // ------------------ REMOVING ------------------
        uint cnt;
        while (setStorage.get().length > 0) {
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

    function test_RevertIfTooManyElements_Insert(uint seed) public {
        seed = bound(seed, 101, type(uint).max);
        delete setStorage;

        for (uint i = 0; i < Set.MAX_ELEMENTS; ++i) {
            assertEq(
                setStorage.insert(
                    address(
                        uint160(uint(bytes32(keccak256(abi.encode(seed, i)))))
                    )
                ),
                true
            );
        }

        vm.expectRevert(Set.TooManyElements.selector);
        setStorage.insert(
            address(uint160(uint(bytes32(keccak256(abi.encode(seed, seed))))))
        );
    }

    function test_insert_first(address element) public {
        bool wasInserted = setStorage.insert(element);

        assertTrue(wasInserted);
        assertEq(setStorage.numElements, 1);
        assertEq(setStorage.firstElement, element);
    }

    function test_insert_second(address elementA, address elementB) public {
        vm.assume(elementA != elementB);

        assertTrue(setStorage.insert(elementA));
        assertTrue(setStorage.insert(elementB));
        assertEq(setStorage.numElements, 2);
        assertEq(setStorage.firstElement, elementA);
    }

    function test_insert_duplicateOfFirstElement(address element) public {
        assertTrue(setStorage.insert(element));
        assertFalse(setStorage.insert(element));
        assertEq(setStorage.numElements, 1);
        assertEq(setStorage.firstElement, element);
    }

    function test_insert_duplicateOfArrayElement(
        address elementA,
        address elementB
    ) public {
        vm.assume(elementA != elementB);

        assertTrue(setStorage.insert(elementA));
        assertTrue(setStorage.insert(elementB));
        assertFalse(setStorage.insert(elementB));
        assertEq(setStorage.numElements, 2);
        assertEq(setStorage.firstElement, elementA);
    }

    function test_insert_and_contains_20Elements() public {
        for (uint i = 0; i < 20; i++) {
            address e = address(uint160(uint256(i)));
            address eNext = address(uint160(uint256(i + 1)));
            assertTrue(setStorage.insert(e));
            assertTrue(setStorage.contains(e));
            assertFalse(setStorage.contains(eNext));
        }

        assertEq(setStorage.numElements, 20);
    }

    function test_contains_empty(address e) public {
        assertFalse(setStorage.contains(e));
    }

    function test_contains_firstElement(address e) public {
        setStorage.insert(e);
        assertTrue(setStorage.contains(e));
    }

    function test_remove_empty(address e) public {
        assertFalse(setStorage.remove(e));
        assertEq(setStorage.numElements, 0);
    }

    function test_remove_firstElement(address e) public {
        setStorage.insert(e);
        assertTrue(setStorage.remove(e));
        assertEq(setStorage.numElements, 0);
    }

    function test_remove_second(address elementA, address elementB) public {
        vm.assume(elementA != elementB);
        setStorage.insert(elementA);
        setStorage.insert(elementB);
        assertTrue(setStorage.remove(elementB));
        assertEq(setStorage.numElements, 1);
        assertTrue(setStorage.remove(elementA));
        assertEq(setStorage.numElements, 0);
    }
}
