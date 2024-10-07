// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../../src/Set.sol";

contract SetHarness {

    SetStorage public setStorage;

    function insert(
        address element
    ) external returns (bool wasInserted) {
        return Set.insert(setStorage, element);
    }

    function remove(
        address element
    ) external returns (bool) {
        return Set.remove(setStorage, element);
    }

    function reorder(uint8 index1, uint8 index2) external  {
        Set.reorder(setStorage, index1, index2);
    }

    function contains(address elem) external view returns (bool) {
        return Set.contains(setStorage, elem);
    }

}