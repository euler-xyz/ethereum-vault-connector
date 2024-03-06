// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.19;

/// @title Events
/// @author Euler Labs (https://www.eulerlabs.com/)
/// @notice This contract implements the events for the Ethereum Vault Connector.
contract Events {
    event OwnerRegistered(bytes19 indexed addressPrefix, address indexed owner);
    event LockdownModeStatus(bytes19 indexed addressPrefix, bool enabled);
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
