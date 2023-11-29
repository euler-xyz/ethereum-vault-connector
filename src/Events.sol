// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.19;

/// @title Events
/// @author Euler Labs (https://www.eulerlabs.com/)
/// @notice This contract implements the events for the Ethereum Vault Connector.
contract Events {
    event OwnerRegistered(uint152 indexed addressPrefix, address indexed owner);
    event NonceUsed(uint152 indexed addressPrefix, uint256 nonce);
    event OperatorStatus(uint152 indexed addressPrefix, address indexed operator, uint256 accountOperatorAuthorized);
    event CollateralStatus(address indexed account, address indexed collateral, bool enabled);
    event ControllerStatus(address indexed account, address indexed controller, bool enabled);
    event CallWithContext(
        address indexed caller, address indexed targetContract, address indexed onBehalfOfAccount, bytes4 selector
    );
}
