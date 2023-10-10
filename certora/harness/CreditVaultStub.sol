// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import {CreditVaultConnector} from "../../src/CreditVaultConnector.sol";
import {ICreditVault} from "../../src/interfaces/ICreditVault.sol";

contract CreditVaultStub is ICreditVault {
    CreditVaultConnector cvc;
    bool public doRevert;
    bool public doReenter;
    bool public retIsValid;

    /// @dev Stubbed function. Must provide a CVL summarization.
    function disableController(address account) external {
        if(doRevert) revert();
        if(doReenter) _reenter();
    }

    /// @dev Stubbed function. Must provide a CVL summarization.
    function checkAccountStatus(
        address account,
        address[] calldata collaterals
    ) external returns (bool isValid, bytes memory data) {
        if(doRevert) revert();
        if(doReenter) _reenter();
        return (retIsValid, "");
    }

    /// @dev Stubbed function. Must provide a CVL summarization.
    function checkVaultStatus()
        external
        returns (bool isValid, bytes memory data) {
            if(doRevert) revert();
            if(doReenter) _reenter();
            return (retIsValid, "");
        }

    function _reenter() internal {
        cvc.getExecutionContext(address(455));
    }
}