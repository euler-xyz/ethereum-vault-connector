// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.19;

type OWBF is uint256;

/// @title OwnerBitField
/// @author Euler Labs (https://www.eulerlabs.com/)
/// @notice This library provides functions for managing the owner bit field in the Ethereum Vault Connector.
/// @dev The owner bit field is a bit field that stores the following information:
/// @dev - owner - the address recognized as owner of the address prefix
/// @dev - permit only flag - used to indicate that the calls are only executable through the permit function for the
/// corresponding address prefix
/// @dev - ignore attester flag - used to indicate that the attester signature should be ignored for the corresponding
/// address prefix
/// @dev - lockdown mode flag - used to indicate that the calls are disabled for the corresponding address prefix
library OwnerBitField {
    uint256 internal constant OWNER_MASK = 0x000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
    uint256 internal constant PERMIT_ONLY_MODE_MASK = 0x0000000000000000000000FF0000000000000000000000000000000000000000;
    uint256 internal constant ATTESTER_DISABLED_MODE_MASK =
        0x00000000000000000000FF000000000000000000000000000000000000000000;
    uint256 internal constant LOCKDOWN_MODE_MASK = 0x000000000000000000FF00000000000000000000000000000000000000000000;

    // None of the functions below modifies the state. All the functions operate on the copy
    // of the execution context and return its modified value as a result. In order to update
    // one should use the result of the function call as a new execution context value.

    function getOwner(OWBF self) internal pure returns (address result) {
        result = address(uint160(OWBF.unwrap(self) & OWNER_MASK));
    }

    function setOwner(OWBF self, address owner) internal pure returns (OWBF result) {
        result = OWBF.wrap((OWBF.unwrap(self) & ~OWNER_MASK) | uint160(owner));
    }

    function isPermitOnlyMode(OWBF self) internal pure returns (bool result) {
        result = OWBF.unwrap(self) & PERMIT_ONLY_MODE_MASK != 0;
    }

    function setPermitOnlyMode(OWBF self) internal pure returns (OWBF result) {
        result = OWBF.wrap(OWBF.unwrap(self) | PERMIT_ONLY_MODE_MASK);
    }

    function clearPermitOnlyMode(OWBF self) internal pure returns (OWBF result) {
        result = OWBF.wrap(OWBF.unwrap(self) & ~PERMIT_ONLY_MODE_MASK);
    }

    function isAttesterDisabledMode(OWBF self) internal pure returns (bool result) {
        result = OWBF.unwrap(self) & ATTESTER_DISABLED_MODE_MASK != 0;
    }

    function setAttesterDisabledMode(OWBF self) internal pure returns (OWBF result) {
        result = OWBF.wrap(OWBF.unwrap(self) | ATTESTER_DISABLED_MODE_MASK);
    }

    function clearAttesterDisabledMode(OWBF self) internal pure returns (OWBF result) {
        result = OWBF.wrap(OWBF.unwrap(self) & ~ATTESTER_DISABLED_MODE_MASK);
    }

    function isLockdownMode(OWBF self) internal pure returns (bool result) {
        result = OWBF.unwrap(self) & LOCKDOWN_MODE_MASK != 0;
    }

    function setLockdown(OWBF self) internal pure returns (OWBF result) {
        result = OWBF.wrap(OWBF.unwrap(self) | LOCKDOWN_MODE_MASK);
    }

    function clearLockdown(OWBF self) internal pure returns (OWBF result) {
        result = OWBF.wrap(OWBF.unwrap(self) & ~LOCKDOWN_MODE_MASK);
    }
}
