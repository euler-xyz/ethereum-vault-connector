// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.19;

type OBF is uint256;

/// @title OwnerBitField
/// @author Euler Labs (https://www.eulerlabs.com/)
/// @notice This library provides functions for managing the owner bit field in the Ethereum Vault Connector.
/// @dev The owner bit field is a bit field that stores the following information:
/// @dev - owner - the address recognized as owner of the address prefix
/// @dev - lockdown mode flag - used to indicate that the EVC functionality is limited for a given address prefix
library OwnerBitField {
    uint256 internal constant OWNER_MASK = 0x000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
    uint256 internal constant LOCKDOWN_MODE_MASK = 0x0000000000000000000000FF0000000000000000000000000000000000000000;

    // None of the functions below modifies the state. All the functions operate on the copy
    // of the owner bit field and return its modified value as a result. In order to update
    // one should use the result of the function call as a new owner bit field value.

    function getOwner(OBF self) internal pure returns (address result) {
        result = address(uint160(OBF.unwrap(self) & OWNER_MASK));
    }

    function setOwner(OBF self, address owner) internal pure returns (OBF result) {
        result = OBF.wrap((OBF.unwrap(self) & ~OWNER_MASK) | uint160(owner));
    }

    function isLockdownMode(OBF self) internal pure returns (bool result) {
        result = OBF.unwrap(self) & LOCKDOWN_MODE_MASK != 0;
    }

    function setLockdownMode(OBF self, bool value) internal pure returns (OBF result) {
        result =
            value ? OBF.wrap(OBF.unwrap(self) | LOCKDOWN_MODE_MASK) : OBF.wrap(OBF.unwrap(self) & ~LOCKDOWN_MODE_MASK);
    }
}
