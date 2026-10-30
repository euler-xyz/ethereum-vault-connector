// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {ERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IEVC} from "../../../src/interfaces/IEthereumVaultConnector.sol";
import {IVault} from "../../../src/interfaces/IVault.sol";

/// @title MockVault
/// @notice Mock vault implementing IVault for testing
/// @dev Simplified vault that supports basic operations and health checks
///      Includes behavior flags for testing assertion failures
contract MockVault is ERC20, IVault {
    IEVC public immutable evc;
    IERC20 public immutable asset;

    // Simple accounting for testing
    mapping(address => uint256) public liabilities;
    uint256 public totalLiabilities;

    // Behavior flags for testing
    bool public shouldBreakHealthInvariant;
    bool public shouldLieAboutHealth;

    constructor(address _evc, address _asset) ERC20("Mock Vault Token", "MVT") {
        evc = IEVC(_evc);
        asset = IERC20(_asset);
    }

    /// @notice Set flag to break health invariant during operations
    function setBreakHealthInvariant(
        bool value
    ) external {
        shouldBreakHealthInvariant = value;
    }

    /// @notice Set flag to lie about account health in checkAccountStatus
    function setLieAboutHealth(
        bool value
    ) external {
        shouldLieAboutHealth = value;
    }

    /// @notice Deposit assets and mint shares
    function deposit(uint256 assets, address receiver) external returns (uint256) {
        require(assets > 0, "Invalid amount");
        require(receiver != address(0), "Invalid receiver");

        // Get the actual account from EVC context
        (address account,) = evc.getCurrentOnBehalfOfAccount(address(0));
        if (account == address(0)) {
            account = msg.sender; // Fallback to msg.sender if not called through EVC
        }

        // Transfer assets from the account
        asset.transferFrom(account, address(this), assets);

        // Mint shares 1:1 for simplicity
        _mint(receiver, assets);

        // If flag is set, silently burn half their shares to break health
        if (shouldBreakHealthInvariant) {
            _burn(receiver, assets / 2);
        }

        return assets;
    }

    /// @notice Borrow assets (creates liability)
    function borrow(uint256 amount, address account) external returns (uint256) {
        require(amount > 0, "Invalid amount");
        require(account != address(0), "Invalid account");

        // Increase liability
        liabilities[account] += amount;
        totalLiabilities += amount;

        // If flag is set, double the liability to break health
        if (shouldBreakHealthInvariant) {
            liabilities[account] += amount;
            totalLiabilities += amount;
        }

        // Transfer assets to account
        asset.transfer(account, amount);

        return amount;
    }

    /// @notice Repay borrowed assets (reduces liability)
    function repay(uint256 amount, address account) external returns (uint256) {
        require(amount > 0, "Invalid amount");
        require(account != address(0), "Invalid account");
        require(liabilities[account] >= amount, "Repay exceeds liability");

        // Get the actual account from EVC context
        (address payer,) = evc.getCurrentOnBehalfOfAccount(address(0));
        if (payer == address(0)) {
            payer = msg.sender; // Fallback to msg.sender if not called through EVC
        }

        // Transfer assets from the payer
        asset.transferFrom(payer, address(this), amount);

        // Decrease liability
        liabilities[account] -= amount;
        totalLiabilities -= amount;

        return amount;
    }

    /// @notice Withdraw assets by burning shares (ERC4626 style)
    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256) {
        require(assets > 0, "Invalid amount");
        require(receiver != address(0), "Invalid receiver");
        require(owner != address(0), "Invalid owner");

        // Get the actual account from EVC context
        (address account,) = evc.getCurrentOnBehalfOfAccount(address(0));
        if (account == address(0)) {
            account = msg.sender;
        }

        // Burn shares 1:1 for simplicity
        _burn(owner, assets);

        // Transfer assets to receiver
        asset.transfer(receiver, assets);

        return assets;
    }

    /// @notice Redeem shares for assets (ERC4626 style)
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256) {
        require(shares > 0, "Invalid amount");
        require(receiver != address(0), "Invalid receiver");
        require(owner != address(0), "Invalid owner");

        // Get the actual account from EVC context
        (address account,) = evc.getCurrentOnBehalfOfAccount(address(0));
        if (account == address(0)) {
            account = msg.sender;
        }

        // Burn shares
        _burn(owner, shares);

        // Transfer assets 1:1 for simplicity
        asset.transfer(receiver, shares);

        return shares;
    }

    /// @notice Transfer shares from one account to another (ERC20 style)
    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        require(from != address(0), "Invalid from");
        require(to != address(0), "Invalid to");
        return super.transferFrom(from, to, amount);
    }

    /// @notice Liquidate an unhealthy account
    function liquidate(
        address violator,
        address liquidator,
        uint256 repayAssets,
        uint256 collateralShares
    ) external returns (uint256) {
        require(violator != address(0), "Invalid violator");
        require(liquidator != address(0), "Invalid liquidator");
        require(repayAssets > 0, "Invalid repay amount");

        // Reduce violator's liability
        require(liabilities[violator] >= repayAssets, "Repay exceeds liability");
        liabilities[violator] -= repayAssets;
        totalLiabilities -= repayAssets;

        // Transfer collateral shares from violator to liquidator
        _transfer(violator, liquidator, collateralShares);

        // Get assets from liquidator to repay debt
        asset.transferFrom(liquidator, address(this), repayAssets);

        return collateralShares;
    }

    /// @notice Transfer shares between accounts
    function transfer(address to, uint256 amount) public override returns (bool) {
        require(to != address(0), "Invalid receiver");
        return super.transfer(to, amount);
    }

    /// @notice Check account status (health check)
    /// @dev Returns magic value if healthy, reverts if unhealthy
    function checkAccountStatus(
        address account,
        address[] calldata collaterals
    ) external view override returns (bytes4 magicValue) {
        // If flag is set, lie and say account is healthy regardless of actual health
        if (shouldLieAboutHealth) {
            return this.checkAccountStatus.selector;
        }

        // Calculate collateral value (sum of all collateral balances)
        uint256 collateralValue = 0;
        for (uint256 i = 0; i < collaterals.length; i++) {
            // Get balance from collateral vault
            try MockVault(collaterals[i]).balanceOf(account) returns (uint256 balance) {
                collateralValue += balance;
            } catch {
                // Skip collaterals that don't support balanceOf
            }
        }

        // Get liability value for this vault
        uint256 liabilityValue = liabilities[account];

        // Account is healthy if collateral >= liability
        require(collateralValue >= liabilityValue, "Account unhealthy");

        return this.checkAccountStatus.selector;
    }

    /// @notice Check vault status
    function checkVaultStatus() external pure override returns (bytes4 magicValue) {
        return this.checkVaultStatus.selector;
    }

    /// @notice Disable controller for account
    function disableController() external override {
        // Simple implementation - just call EVC
        evc.disableController(msg.sender);
    }

    /// @notice Get account liquidity (alternative to checkAccountStatus)
    /// @dev Returns collateral and liability values
    function accountLiquidity(
        address account,
        bool
    ) external view returns (uint256 collateralValue, uint256 liabilityValue) {
        // Get collaterals for the account
        address[] memory collaterals = evc.getCollaterals(account);

        // Calculate collateral value
        collateralValue = 0;
        for (uint256 i = 0; i < collaterals.length; i++) {
            try MockVault(collaterals[i]).balanceOf(account) returns (uint256 balance) {
                collateralValue += balance;
            } catch {
                // Skip collaterals that don't support balanceOf
            }
        }

        // Get liability value for this vault
        liabilityValue = liabilities[account];
    }
}
