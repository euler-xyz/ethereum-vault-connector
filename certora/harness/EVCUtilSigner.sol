// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../../src/interfaces/IERC1271.sol";
import "../../src/utils/EVCUtil.sol";

contract EVCUtilSigner is IERC1271, EVCUtil {
    address public authorizedAccount;

    constructor(address _evc) EVCUtil(_evc) {}

    function isValidSignature(bytes32, bytes memory) external view returns (bytes4) {
        return _msgSender() == authorizedAccount ? this.isValidSignature.selector : bytes4(0xffffffff);
    }
}
