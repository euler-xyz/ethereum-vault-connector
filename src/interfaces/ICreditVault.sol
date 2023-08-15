// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

interface ICreditVault {
    function disableController(address account) external;

    function checkAccountStatus(
        address account,
        address[] calldata collaterals
    ) external returns (bool isValid, bytes memory data);

    function checkVaultStatus()
        external
        returns (bool isValid, bytes memory data);
}
