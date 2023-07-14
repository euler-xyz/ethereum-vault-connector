// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

abstract contract UnstructuredStorageBytes {
    bytes32 immutable private bytesLengthPosition;
    bytes32 immutable private bytesDataPosition;

    constructor(bytes memory bytesSlotInitValue) {
        bytesLengthPosition = keccak256(bytesSlotInitValue);
        bytesDataPosition = keccak256(abi.encodePacked(bytesLengthPosition));
    }

    // assembly functions implemented with help of the following stackoverflow topic:
    // https://ethereum.stackexchange.com/questions/126269/how-to-store-and-retrieve-string-which-is-more-than-32-bytesor-could-be-less-th
    function getBytes() internal view returns (bytes memory bytesToGet) {
        bytes32 lengthPosition = bytesLengthPosition;
        bytes32 dataPosition = bytesDataPosition;

        assembly {
            let length := sload(lengthPosition)

            // Check if what type of array we are dealing with
            // The return array will need to be taken from STORAGE
            // respecting the STORAGE layout of bytes, but rebuilt
            // in MEMORY according to the MEMORY layout of bytes.
            switch and(length, 0x01)

            // Short array
            case 0x00 {
                let decodedLength := div(and(length, 0xFF), 2)

                // Add length in first 32 byte slot 
                mstore(bytesToGet, decodedLength)
                mstore(add(bytesToGet, 0x20), and(length, not(0xFF)))
                mstore(0x40, add(bytesToGet, 0x40))
            }

            // Long array
            case 0x01 {
                let decodedLength := div(length, 2)
                let i := 0

                mstore(bytesToGet, decodedLength)
                
                // Write to memory as many blocks of 32 bytes as necessary taken from data storage variable slot + i
                for {} lt(mul(i, 0x20), decodedLength) {i := add(i, 0x01)} {
                    mstore(add(add(bytesToGet, 0x20), mul(i, 0x20)), sload(add(dataPosition, i)))
                }

                mstore(0x40, add(bytesToGet, add(0x20, mul(i, 0x20))))
            }
        }
    }

    function setBytes(bytes memory bytesToSet) internal {
        bytes32 lengthPosition = bytesLengthPosition;
        bytes32 dataPosition = bytesDataPosition;

        assembly {
            let length := mload(bytesToSet)

            switch gt(length, 0x1F)

            // If bytes length <= 31 we store a short array
            // length storage variable layout : 
            // bytes 0 - 31 : bytes data
            // byte 32 : length * 2
            // data storage variable is UNUSED in this case
            case 0x00 {
                switch eq(length, 0) 
                
                case 0x00 { 
                    sstore(lengthPosition, or(mload(add(bytesToSet, 0x20)), mul(length, 2))) 
                }

                case 0x01 { 
                    sstore(lengthPosition, 0) 
                }
            }

            // If bytes length > 31 we store a long array
            // length storage variable layout :
            // bytes 0 - 32 : length * 2 + 1
            // data storage layout :
            // bytes 0 - 32 : bytes data
            // If more than 32 bytes are required for the bytes we write them
            // to the slot(s) following the slot of the data storage variable
            case 0x01 {
                 // Store length * 2 + 1 at slot length
                sstore(lengthPosition, add(mul(length, 2), 1))

                // Then store the string content by blocks of 32 bytes
                for {let i:= 0} lt(mul(i, 0x20), length) {i := add(i, 0x01)} {
                    sstore(add(dataPosition, i), mload(add(bytesToSet, mul(add(i, 1), 0x20))))
                }
            }
        }
    }

    function clearBytes() internal {
        bytes32 lengthPosition = bytesLengthPosition;
        assembly { sstore(lengthPosition, 0) }
    }

    function areBytesEmpty() internal view returns (bool areEmpty) {
        bytes32 lengthPosition = bytesLengthPosition;
        assembly { areEmpty := eq(sload(lengthPosition), 0) }
    }
}
