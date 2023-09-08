// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../../src/Set.sol";

contract SetHarness {
    using Set for SetStorage;

    SetStorage public set;

    function insert(address element) external returns (bool wasInserted) {
        return set.insert(element);
    }

    function remove(address element) external returns (bool wasRemoved) {
        return set.remove(element);
    }

    function MAX_ELEMENTS() external view returns (uint) {
        return Set.MAX_ELEMENTS;
    }

    function numElements() external view returns (uint8) {
        return set.numElements;
    }

    function firstElement() external view returns (address) {
        return set.firstElement;
    }

    function get() external view returns (address[] memory) {
        return set.get();
    }

    function contains(address element) external view returns (bool) {
        return set.contains(element);
    }

    function elementsArrayAt(uint i) external view returns (address) {
        return set.elements[i];
    }
}