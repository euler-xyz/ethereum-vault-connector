// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../../src/interfaces/IEthereumVaultConnector.sol";

contract PermitCaller {
    IEVC public evc;
    address public signer;
    uint256 public nonceNamespace;
    uint256 public nonce;
    uint256 public deadline;
    uint256 public value;
    bytes public data;
    bytes public signature;

    function onEVCCall() external {
        evc.permit(signer, address(this), nonceNamespace, nonce, deadline, value, data, signature);
    }
}
