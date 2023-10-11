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
    ) public {
        cvc.permitHash(signer, nonceNamespace, nonce, deadline, data);
    }

    function testGas_haveCommonOwner(address a, address b) public {
        cvc.haveCommonOwner(a, b);
    }
}
