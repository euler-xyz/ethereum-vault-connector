// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

interface ICreditVault {
    /// @notice Disables a controller (this vault) for an account.
    /// @dev A controller is a vault that has been chosen for an account to have special control over account’s balances in the enabled collaterals vaults. User calls this function in order for the vault to disable itself for the account if the conditions are met (i.e. user has repaid debt in full).
    /// @param account The address for which the controller is being disabled.
    function disableController(address account) external;

    /// @notice Checks the status of an account and returns whether it is valid or not.
    /// @param account The address of the account to be checked.
    /// @return isValid A boolean value that indicates whether the account status is valid or not.
    /// @return data Bytes data that indicates the reason why the account status is not valid. Irrelevant if the account status is valid.
    function checkAccountStatus(
        address account,
        address[] calldata collaterals
    ) external returns (bool isValid, bytes memory data);

    /// @notice Checks the status of the vault and returns whether it is valid or not.
    /// @return isValid A boolean value that indicates whether the vault status is valid or not.
    /// @return data Bytes data that indicates the reason why the vault status is not valid. Irrelevant if the vault status is valid.
    function checkVaultStatus()
        external
        returns (bool isValid, bytes memory data);
}
