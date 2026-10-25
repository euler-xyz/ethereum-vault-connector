// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../../src/interfaces/IEthereumVaultConnector.sol";
import "../../src/interfaces/IERC1271.sol";

// Answers ERC-1271 by authenticating its caller the way EVCUtil._msgSender() did before EVC v1.0.2.
contract ContextSigner is IERC1271 {
    IEVC public evc;
    address public authorizedAccount;

    function isValidSignature(bytes32, bytes memory) external view returns (bytes4) {
        address sender = msg.sender;

        if (sender == address(evc)) {
            (sender,) = evc.getCurrentOnBehalfOfAccount(address(0));
        }

        return sender == authorizedAccount ? this.isValidSignature.selector : bytes4(0xffffffff);
    }
}
