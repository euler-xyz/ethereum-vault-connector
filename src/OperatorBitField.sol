// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.19;

type OPBF is uint256;

/// @title OperatorBitField
/// @author Euler Labs (https://www.eulerlabs.com/)
/// @notice This library provides functions for managing the operator bit field in the Ethereum Vault Connector.
/// @dev The operator bit field is a 256-position binary array, where each 1 corresponds to the account for which given
/// feature is enabled.
library OperatorBitField {
    // None of the functions below modifies the state. All the functions operate on the copy
    // of the execution context and return its modified value as a result. In order to update
    // one should use the result of the function call as a new execution context value.

    function isBitSet(OPBF self, address owner, address account) internal pure returns (bool result) {
        return OPBF.unwrap(self) & getBitMask(owner, account) != 0;
    }

    function setBit(OPBF self, address owner, address account) internal pure returns (OPBF result) {
        return OPBF.wrap(OPBF.unwrap(self) | getBitMask(owner, account));
    }

    function clearBit(OPBF self, address owner, address account) internal pure returns (OPBF result) {
        return OPBF.wrap(OPBF.unwrap(self) & ~getBitMask(owner, account));
    }

    function getBitMask(address owner, address account) private pure returns (uint256 result) {
        // The bitMask defines for which accounts the given feature is enabled. The bitMask is created from the account
        // number which is a number up to 2^8 in binary, or 256. 1 << (uint160(owner) ^ uint160(account)) transforms
        // that number in an 256-position binary array like 0...010...0, marking the account positionally in a uint256.
        return 1 << (uint160(owner) ^ uint160(account));
    }
}
