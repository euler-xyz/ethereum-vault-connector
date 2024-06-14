// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (interfaces/IERC1271.sol)

pragma solidity >=0.8.0;

/// @dev Interface of the ERC1271 standard signature validation method for
/// contracts as defined in https://eips.ethereum.org/EIPS/eip-1271[ERC-1271].
interface IERC1271 {
    /// @dev Should return whether the signature provided is valid for the provided data
    /// @param hash Hash of the data to be signed
    /// @param signature Signature byte array associated with _data
    /// @return magicValue Must return the bytes4 magic value 0x1626ba7e (which is a selector of this function) when
    /// the signature is valid.
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4 magicValue);
}
