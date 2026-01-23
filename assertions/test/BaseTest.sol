// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {CredibleTest} from "credible-std/CredibleTest.sol";
import {Test} from "forge-std/Test.sol";
import {EthereumVaultConnector} from "../../src/EthereumVaultConnector.sol";
import {IEVC} from "../../src/interfaces/IEthereumVaultConnector.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

/// @title BaseTest
/// @notice Base test contract with common setup logic for all assertion tests
/// @dev Provides standard test users, EVC instance, and helper functions for token/vault setup
abstract contract BaseTest is CredibleTest, Test {
    // Standard test users used across all tests
    address public constant user1 = address(0xBEEF);
    address public constant user2 = address(0xCAFE);
    address public constant user3 = address(0xDEAF);
    address public constant liquidator = address(0x1111);

    // EVC instance - deployed in setUp
    EthereumVaultConnector public evc;

    /// @notice Base setup - deploys EVC
    /// @dev Child contracts should call this via super.setUp()
    function setUp() public virtual {
        evc = new EthereumVaultConnector();
    }

    /// @notice Helper: Give ETH to standard test users
    /// @dev Gives 100 ETH to user1 and user2
    function setupUserETH() internal {
        vm.deal(user1, 100 ether);
        vm.deal(user2, 100 ether);
    }

    /// @notice Helper: Mint tokens to standard test users
    /// @param token The token to mint
    /// @param amount Amount to mint to each user
    function mintTokensToUsers(MockERC20 token, uint256 amount) internal {
        token.mint(user1, amount);
        token.mint(user2, amount);
    }

    /// @notice Helper: Approve vault to spend tokens for standard users
    /// @param token The token to approve
    /// @param vault The vault address to approve
    function approveVaultForUsers(MockERC20 token, address vault) internal {
        vm.prank(user1);
        token.approve(vault, type(uint256).max);
        vm.prank(user2);
        token.approve(vault, type(uint256).max);
    }

    /// @notice Helper: Full setup for a token (mint + approve)
    /// @param token The token to setup
    /// @param vault The vault to approve
    /// @param amount Amount to mint to each user (default: 1M tokens)
    function setupToken(MockERC20 token, address vault, uint256 amount) internal {
        mintTokensToUsers(token, amount);
        approveVaultForUsers(token, vault);
    }

    /// @notice Helper: Setup multiple tokens with same vault and amount
    /// @param tokens Array of tokens to setup
    /// @param vault The vault to approve for all tokens
    /// @param amount Amount to mint to each user for each token
    function setupTokens(MockERC20[] memory tokens, address vault, uint256 amount) internal {
        for (uint256 i = 0; i < tokens.length; i++) {
            setupToken(tokens[i], vault, amount);
        }
    }
}
