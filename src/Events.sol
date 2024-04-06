// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.19;

/// @title Events
/// @author Euler Labs (https://www.eulerlabs.com/)
/// @notice This contract implements the events for the Ethereum Vault Connector.
contract Events {
    event OwnerRegistered(bytes19 indexed addressPrefix, address indexed owner);
    event LockdownModeStatus(bytes19 indexed addressPrefix, bool enabled);
    event PermitDisabledModeStatus(bytes19 indexed addressPrefix, bool enabled);

    /// @notice Emitted when the nonce status is updated for a given address prefix and nonce namespace.
    /// @param addressPrefix The prefix of the address for which the nonce status is updated.
    /// @param nonceNamespace The namespace of the nonce being updated.
    /// @param oldNonce The previous nonce value before the update.
    /// @param newNonce The new nonce value after the update.
    event NonceStatus(
        bytes19 indexed addressPrefix, uint256 indexed nonceNamespace, uint256 oldNonce, uint256 newNonce
    );
    event NonceUsed(bytes19 indexed addressPrefix, uint256 indexed nonceNamespace, uint256 nonce);
    event OperatorStatus(bytes19 indexed addressPrefix, address indexed operator, uint256 accountOperatorAuthorized);
    event CollateralStatus(address indexed account, address indexed collateral, bool enabled);
    event ControllerStatus(address indexed account, address indexed controller, bool enabled);
    event CallWithContext(
        address indexed caller,
        bytes19 indexed onBehalfOfAddressPrefix,
        address onBehalfOfAccount,
        address indexed targetContract,
        bytes4 selector
    );
    event AccountStatusCheck(address indexed account, address indexed controller);
    event VaultStatusCheck(address indexed vault);
}
