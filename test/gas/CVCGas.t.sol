// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../src/CreditVaultConnector.sol";

contract CVCHarness is CreditVaultConnector {
    function permitHash(
        address signer,
        uint nonceNamespace,
        uint nonce,
        uint deadline,
        bytes calldata data
    ) external view returns (bytes32) {
        return getPermitHash(signer, nonceNamespace, nonce, deadline, data);
    }

    function getIsValidERC1271Signature(
        address signer,
        bytes32 hash,
        bytes memory signature
    ) external returns (bool isValid) { // for compatibility with scribble, do not make this view
        return isValidERC1271Signature(signer, hash, signature);
    }
}

contract CVCGas is Test {
    using Set for SetStorage;

    CVCHarness cvc;

    function setUp() public {
        cvc = new CVCHarness();
    }

    function testGas_getPermitHash(
        address signer,
        uint nonceNamespace,
        uint nonce,
        uint deadline,
        bytes calldata data
    ) public view {
        cvc.permitHash(signer, nonceNamespace, nonce, deadline, data);
    }

    function testGas_haveCommonOwner(address a, address b) public view {
        cvc.haveCommonOwner(a, b);
    }

    function testGas_isValidSignature_eoa(
        address signer,
        bytes32 hash,
        bytes memory signature
    ) public {
        vm.assume(signature.length < 100);
        cvc.getIsValidERC1271Signature(signer, hash, signature);
    }

    function testGas_isValidSignature_contract(
        address signer,
        bytes32 hash,
        bytes memory signature
    ) public {
        vm.assume(signer != address(cvc) && uint160(signer) > 1000);
        vm.assume(signature.length < 100);
        vm.etch(signer, "ff");
        cvc.getIsValidERC1271Signature(signer, hash, signature);
    }
}
