// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IPerspective} from "../../src/interfaces/IPerspective.sol";

/// @title MockPerspective
/// @notice A mock perspective for testing that returns true for all vaults or specified vaults
contract MockPerspective is IPerspective {
    mapping(address => bool) public verifiedVaults;
    address[] public verifiedList;
    bool public verifyAll;

    constructor() {
        verifyAll = true; // By default, verify all vaults for easy testing
    }

    /// @notice Set whether to verify all vaults by default
    function setVerifyAll(
        bool _verifyAll
    ) external {
        verifyAll = _verifyAll;
    }

    /// @notice Add a vault to the verified list
    function addVerifiedVault(
        address vault
    ) external {
        if (!verifiedVaults[vault]) {
            verifiedVaults[vault] = true;
            verifiedList.push(vault);
        }
    }

    /// @notice Remove a vault from the verified list
    function removeVerifiedVault(
        address vault
    ) external {
        verifiedVaults[vault] = false;
    }

    function name() external pure override returns (string memory) {
        return "MockPerspective";
    }

    function perspectiveVerify(
        address,
        bool
    ) external pure override {
        // No-op for mock
    }

    function isVerified(
        address vault
    ) external view override returns (bool) {
        if (verifyAll) return true;
        return verifiedVaults[vault];
    }

    function verifiedLength() external view override returns (uint256) {
        return verifiedList.length;
    }

    function verifiedArray() external view override returns (address[] memory) {
        return verifiedList;
    }
}
