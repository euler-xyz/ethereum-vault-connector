// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

abstract contract ReentrancyGuard {
    error Reentrancy();
    error MustBeNonReentrant();
    
    bytes32 immutable private reentrancyGuardPosition;
    uint constant internal REENTRANCY_GUARD_UNDEFINED = 0;
    uint constant internal REENTRANCY_GUARD_INIT = 1;
    uint constant internal REENTRANCY_GUARD_BUSY = 2;
    
    constructor(bytes memory reentrancyGuardSlotInitValue) {
        reentrancyGuardPosition = keccak256(reentrancyGuardSlotInitValue);
        setReentrancyGuard(REENTRANCY_GUARD_INIT);
    }

    modifier nonReentrant() {
        // for proxy compatibility
        if (getReentrancyGuard() == REENTRANCY_GUARD_UNDEFINED) setReentrancyGuard(REENTRANCY_GUARD_INIT);

        testReentrancyGuard(REENTRANCY_GUARD_INIT, Reentrancy.selector);

        setReentrancyGuard(REENTRANCY_GUARD_BUSY);
        _;
        setReentrancyGuard(REENTRANCY_GUARD_INIT);
    }

    modifier nonReentrantRO() {
        testReentrancyGuard(REENTRANCY_GUARD_INIT, Reentrancy.selector);
        _;
    }

    function getReentrancyGuard() internal view returns (uint reentrancyGuard) {
        bytes32 position = reentrancyGuardPosition;
        assembly { reentrancyGuard := sload(position) }
    }

    function setReentrancyGuard(uint reentrancyGuard) internal {
        bytes32 position = reentrancyGuardPosition;
        assembly { sstore(position, reentrancyGuard) }
    }

    function testReentrancyGuard(uint expectedReentrancyGuard, bytes4 errorSelector) internal view {
        bytes32 position = reentrancyGuardPosition;
        assembly {
            if iszero(eq(sload(position), expectedReentrancyGuard)) {
                let ptr := mload(0x40)
                mstore(ptr, errorSelector)
                revert(ptr, 4)
            }
        }
    }
}
