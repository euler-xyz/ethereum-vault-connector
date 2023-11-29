// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.19;

/// @title IVault
/// @author Euler Labs (https://www.eulerlabs.com/)
/// @notice This interface defines the methods for the Vault for the purpose of integration with the Ethereum Vault
/// Connector.
interface IVault {
    /// @notice Disables a controller (this vault) for an account.
    /// @dev A controller is a vault that has been chosen for an account to have special control over account’s
    /// balances in the enabled collaterals vaults. User calls this function in order for the vault to disable itself
    /// for the account if the conditions are met (i.e. user has repaid debt in full).
    /// @param account The address for which the controller is being disabled.
    function disableController(address account) external;

    /// @notice Checks the status of an account.
    /// @param account The address of the account to be checked.
    /// @return magicValue Must return the bytes4 magic value 0xb168c58f (which is a selector of this function) when
    /// account status is valid, or revert otherwise.
    function checkAccountStatus(address account, address[] calldata collaterals) external returns (bytes4 magicValue);

    /// @notice Checks the status of the vault.
    /// @return magicValue Must return the bytes4 magic value 0x4b3d1223 (which is a selector of this function) when
    /// account status is valid, or revert otherwise.
    function checkVaultStatus() external returns (bytes4 magicValue);
}
