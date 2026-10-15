// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {ERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {ERC4626} from "lib/openzeppelin-contracts/contracts/token/ERC20/extensions/ERC4626.sol";

/// @title MockSharePriceVault
/// @notice Mock ERC4626 vault for testing VaultSharePriceAssertion
/// @dev Allows manual manipulation of totalAssets to simulate share price changes
contract MockSharePriceVault is ERC4626 {
    uint256 private _totalAssets;

    // Events for bad debt socialization simulation
    event Repay(address indexed account, uint256 assets);

    constructor(ERC20 assetToken) ERC4626(assetToken) ERC20("Mock Vault", "MV") {}

    function setTotalAssets(uint256 assets) external {
        _totalAssets = assets;
    }

    function totalAssets() public view override returns (uint256) {
        return _totalAssets;
    }

    function increaseSharePrice(uint256 amount) external {
        _totalAssets += amount;
        // Keep total supply the same to increase share price
    }

    function decreaseSharePrice(uint256 amount) external {
        require(_totalAssets >= amount, "Insufficient assets");
        _totalAssets -= amount;
        // Keep total supply the same to decrease share price
        // No events emitted - this simulates malicious share price decrease
    }

    function decreaseSharePriceWithBadDebt(uint256 amount) external {
        require(_totalAssets >= amount, "Insufficient assets");
        _totalAssets -= amount;
        // Keep total supply the same to decrease share price

        // Emit events to simulate bad debt socialization as per Euler whitepaper:
        // - Repay event from liquidator (not address(0))
        // - Withdraw event from address(0)
        address liquidator = address(0x1234567890123456789012345678901234567890); // Mock liquidator
        emit Repay(liquidator, amount);
        emit Withdraw(address(0), address(0), address(0), amount, 0);
    }

    function noOp() external {
        // Do nothing
    }

    // Required IVault interface functions
    function checkVaultStatus() external pure returns (bytes4) {
        return this.checkVaultStatus.selector;
    }

    // Required ERC4626 functions (simplified for testing)
    function deposit(uint256, address) public pure override returns (uint256) {
        revert("Not implemented for testing");
    }

    function mint(uint256 shares, address receiver) public override returns (uint256) {
        _mint(receiver, shares);
        return shares;
    }

    function withdraw(uint256, address, address) public pure override returns (uint256) {
        revert("Not implemented for testing");
    }

    function redeem(uint256, address, address) public pure override returns (uint256) {
        revert("Not implemented for testing");
    }

    function maxDeposit(address) public pure override returns (uint256) {
        return type(uint256).max;
    }

    function maxMint(address) public pure override returns (uint256) {
        return type(uint256).max;
    }

    function maxWithdraw(address) public pure override returns (uint256) {
        return type(uint256).max;
    }

    function maxRedeem(address) public pure override returns (uint256) {
        return type(uint256).max;
    }

    function previewDeposit(uint256) public pure override returns (uint256) {
        return 0;
    }

    function previewMint(uint256) public pure override returns (uint256) {
        return 0;
    }

    function previewWithdraw(uint256) public pure override returns (uint256) {
        return 0;
    }

    function previewRedeem(uint256) public pure override returns (uint256) {
        return 0;
    }

    function convertToShares(uint256) public pure override returns (uint256) {
        return 0;
    }

    function convertToAssets(uint256) public pure override returns (uint256) {
        return 0;
    }
}

/// @title MockControllerVault
/// @notice Mock controller vault for testing controlCollateral functionality
/// @dev Simple controller vault that can be used for controlCollateral tests
contract MockControllerVault {
    function checkAccountStatus(address, address[] memory) external pure returns (bytes4) {
        return this.checkAccountStatus.selector;
    }
}
