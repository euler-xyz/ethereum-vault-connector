// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../../src/interfaces/IVault.sol";

// This is a Mock used to check CER-76 which is related to checkAccountStatus
// This Mock models a Vault with an arbitrary checkAccountStatus implementation.
// The related CVL code will allow it to choose any way of deciding whether or 
// not to revert. The functions disableController and checkVaultSTatus 
contract VaultMock is IVault {

    // Not relevant to spec
    function disableController() external {}
    function checkVaultStatus() external returns (bytes4 magicValue) {
        return 0x4b3d1223;
    }

    // In conjunction with the CVL we use this to model
    // that can arbitrarily choose a function to revert
    function shouldRevert(address account, address[] calldata collaterals) internal returns (bool) {
        // This body is overridden by the CVL
        return true;
    }

    // We need to access shouldRevert from CVL while also calling it 
    // within the contract. 
    function shouldRevertHarness(address account, address[] calldata collaterals) external returns (bool) {
        return shouldRevert(account, collaterals);
    }

    function checkAccountStatus(address account, address[] calldata collaterals) external returns (bytes4 magicValue) {
        if(shouldRevert(account, collaterals)) {
            revert("Invalid account");
        } else {
            return 0xb168c58f;
        }
    }
}