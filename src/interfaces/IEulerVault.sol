// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

interface IEulerVault {
    error VaultStatusHookViolation(bytes data);
    function disableController(address account) external payable;
    function checkAccountStatus(address account, address[] calldata collaterals) external view returns (bool isValid);
    function vaultStatusHook(bool initialCall, bytes memory data) external returns (bytes memory result);
}
