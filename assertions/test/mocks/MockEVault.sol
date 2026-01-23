// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {ERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {ERC4626} from "lib/openzeppelin-contracts/contracts/token/ERC20/extensions/ERC4626.sol";
import {IEVC} from "../../../src/interfaces/IEthereumVaultConnector.sol";

/// @title MockEVault
/// @notice Comprehensive mock EVault for testing
/// @dev Implements ERC4626 with additional features: cash tracking, borrow/repay, skim, bad debt socialization
///      All features are enabled by default and work together
contract MockEVault is ERC4626 {
    // ========================================
    // STATE VARIABLES
    // ========================================

    IEVC public immutable evc;

    // Cash tracking (internal accounting)
    uint256 public cash;

    // Borrow tracking
    mapping(address => uint256) public borrows;
    uint256 public totalBorrows;

    // Testing flags
    bool public shouldLiquidateHealthyAccount; // Flag to break liquidation invariant

    // Bad debt socialization tracking
    event DebtSocialized(address indexed account, uint256 amount);

    // ========================================
    // CONSTRUCTOR
    // ========================================

    constructor(IERC20 _asset, IEVC _evc) ERC4626(_asset) ERC20("Mock EVault", "mEV") {
        evc = _evc;
    }

    // ========================================
    // TESTING FLAGS
    // ========================================

    /// @notice Set flag to liquidate healthy accounts (for testing assertion failures)
    function setLiquidateHealthyAccount(
        bool value
    ) external {
        shouldLiquidateHealthyAccount = value;
    }

    // ========================================
    // EVC CONTEXT SUPPORT
    // ========================================

    /// @notice Get the actual account from EVC context or fallback to msg.sender
    function _getActualCaller() internal view returns (address) {
        if (address(evc) != address(0) && msg.sender == address(evc)) {
            (address account,) = evc.getCurrentOnBehalfOfAccount(address(0));
            return account != address(0) ? account : msg.sender;
        }
        return msg.sender;
    }

    // ========================================
    // ERC4626 OVERRIDES WITH CASH TRACKING
    // ========================================

    /// @notice Deposit with EVC context support and cash tracking
    function deposit(uint256 assets, address receiver) public virtual override returns (uint256) {
        address caller = _getActualCaller();
        uint256 shares = previewDeposit(assets);
        _deposit(caller, receiver, assets, shares);
        cash += assets; // Update cash
        return shares;
    }

    /// @notice Mint with EVC context support and cash tracking
    function mint(uint256 shares, address receiver) public virtual override returns (uint256) {
        address caller = _getActualCaller();
        uint256 assets = previewMint(shares);
        _deposit(caller, receiver, assets, shares);
        cash += assets; // Update cash
        return assets;
    }

    /// @notice Withdraw with EVC context support and cash tracking
    function withdraw(uint256 assets, address receiver, address owner) public virtual override returns (uint256) {
        address caller = _getActualCaller();
        uint256 shares = previewWithdraw(assets);
        _withdraw(caller, receiver, owner, assets, shares);
        cash -= assets; // Update cash
        return shares;
    }

    /// @notice Redeem with EVC context support and cash tracking
    function redeem(uint256 shares, address receiver, address owner) public virtual override returns (uint256) {
        address caller = _getActualCaller();
        uint256 assets = previewRedeem(shares);
        _withdraw(caller, receiver, owner, assets, shares);
        cash -= assets; // Update cash
        return assets;
    }

    // ========================================
    // BORROW/REPAY FUNCTIONALITY
    // ========================================

    /// @notice Borrow assets from the vault (creates liability)
    /// @dev Emits Transfer event from ERC20 and Borrow event
    function borrow(uint256 assets, address receiver) public virtual returns (uint256) {
        require(assets > 0, "Invalid amount");
        require(receiver != address(0), "Invalid receiver");

        address caller = _getActualCaller();

        // Transfer assets to receiver
        IERC20(asset()).transfer(receiver, assets);

        // Update cash and borrow tracking
        cash -= assets;
        borrows[caller] += assets;
        totalBorrows += assets;

        // Emit Borrow event
        emit Borrow(caller, assets);

        return assets;
    }

    /// @notice Repay borrowed assets (reduces liability)
    /// @dev Can emit bad debt socialization event if repayer is address(0)
    function repay(uint256 assets, address debtor) external returns (uint256) {
        require(assets > 0, "Invalid amount");
        require(debtor != address(0), "Invalid debtor");

        address caller = _getActualCaller();

        // Transfer assets from caller
        IERC20(asset()).transferFrom(caller, address(this), assets);

        // Update cash and borrow tracking
        cash += assets;

        // Check if this is bad debt socialization (repay from address(0))
        if (caller == address(0)) {
            emit DebtSocialized(debtor, assets);
        }

        borrows[debtor] -= assets;
        totalBorrows -= assets;

        // Emit Repay event
        emit Repay(debtor, assets);

        return assets;
    }

    // ========================================
    // SKIM FUNCTIONALITY
    // ========================================

    /// @notice Skim unaccounted assets (balance > totalAssets)
    /// @dev Legitimately changes exchange rate by claiming excess assets
    function skim(uint256 amount, address receiver) external returns (uint256) {
        // Calculate excess assets (balance - totalAssets)
        uint256 balance = IERC20(asset()).balanceOf(address(this));
        uint256 excess = balance - totalAssets();

        // Skim requested amount (up to excess)
        uint256 skimAmount = amount > excess ? excess : amount;

        // Mint shares for skimmed assets
        uint256 shares = previewDeposit(skimAmount);
        _mint(receiver, shares);

        emit Deposit(msg.sender, receiver, skimAmount, shares);

        return shares;
    }

    // ========================================
    // EVC INTEGRATION (checkAccountStatus, checkVaultStatus)
    // ========================================

    /// @notice Check account status - required for vaults to be enabled as controllers
    /// @dev Returns the function selector as magic value if healthy, reverts if unhealthy
    function checkAccountStatus(address account, address[] memory collaterals) external view returns (bytes4) {
        // Calculate total collateral value
        uint256 collateralValue = 0;
        for (uint256 i = 0; i < collaterals.length; i++) {
            try MockEVault(collaterals[i]).balanceOf(account) returns (uint256 balance) {
                collateralValue += balance;
            } catch {
                // Skip collaterals that don't support balanceOf
            }
        }

        // Get liability value for this account
        uint256 liabilityValue = borrows[account];

        // Account is healthy if collateralValue >= liabilityValue
        require(collateralValue >= liabilityValue, "Account unhealthy");

        return this.checkAccountStatus.selector;
    }

    /// @notice Check vault status - required for EVC
    /// @dev Returns the function selector as magic value
    function checkVaultStatus() external pure returns (bytes4) {
        return this.checkVaultStatus.selector;
    }

    // ========================================
    // COLLATERAL OPERATIONS
    // ========================================

    /// @notice Seize collateral during liquidation (just transfers shares)
    /// @dev Used in controlCollateral scenarios, no assets leave vault
    function seizeCollateral(address from, address to, uint256 shares) external returns (bool) {
        uint256 assets = convertToAssets(shares);
        _transfer(from, to, shares);
        emit Withdraw(address(this), to, from, assets, shares);
        return true;
    }

    /// @notice Get account balance - helper for controlCollateral testing
    function getAccountBalance(
        address account
    ) external view returns (uint256) {
        return balanceOf(account);
    }

    // ========================================
    // ACCOUNT LIQUIDITY (for AccountHealth tests)
    // ========================================

    /// @notice Get account liquidity (collateral value vs liability value)
    /// @dev Used by AccountHealthAssertion tests
    function accountLiquidity(
        address account,
        bool
    ) external view returns (uint256 collateralValue, uint256 liabilityValue) {
        // Get collaterals for the account from EVC
        address[] memory collaterals = evc.getCollaterals(account);

        // Calculate collateral value (sum of all collateral balances)
        collateralValue = 0;
        for (uint256 i = 0; i < collaterals.length; i++) {
            try MockEVault(collaterals[i]).balanceOf(account) returns (uint256 balance) {
                collateralValue += balance;
            } catch {
                // Skip collaterals that don't support balanceOf
            }
        }

        // Get liability value for this vault
        liabilityValue = borrows[account];
    }

    // ========================================
    // BAD DEBT SOCIALIZATION
    // ========================================

    /// @notice Socialize bad debt by burning shares and emitting events
    /// @dev Used in VaultSharePriceAssertion tests
    function socializeBadDebt(address account, uint256 assets) external {
        // Withdraw from address(0) - signals bad debt socialization
        uint256 shares = previewWithdraw(assets);

        // Emit Withdraw event from address(0)
        emit Withdraw(address(0), account, address(0), assets, shares);

        // Also emit Repay to complete the bad debt socialization pattern
        emit Repay(account, assets);

        cash -= assets;
    }

    /// @notice Simulate bad debt socialization that causes rate decrease
    /// @dev Used in VaultExchangeRateSpikeAssertion tests for >5% rate decrease scenarios
    function simulateBadDebtSocialization(
        uint256 lossAmount
    ) external {
        require(cash >= lossAmount, "Insufficient cash");

        // Decrease cash (simulates loss of assets)
        cash -= lossAmount;

        // Emit DebtSocialized event to indicate legitimate rate decrease
        emit DebtSocialized(msg.sender, lossAmount);
    }

    // ========================================
    // LIQUIDATION
    // ========================================

    /// @notice Liquidate an unhealthy account
    /// @param violator Address that may be in collateral violation
    /// @param collateral Collateral to be seized
    /// @param repayAssets Amount of underlying debt to transfer
    /// @param minYieldBalance Minimum acceptable collateral to transfer
    /// @dev Transfers debt from violator to liquidator (caller)
    ///      Transfers collateral shares from violator to liquidator
    ///      If shouldLiquidateHealthyAccount flag is set, adds extra debt to violator to break health
    function liquidate(address violator, address collateral, uint256 repayAssets, uint256 minYieldBalance) external {
        require(violator != address(0), "Invalid violator");
        require(collateral != address(0), "Invalid collateral");
        require(repayAssets > 0, "Invalid repay amount");

        address liquidator = _getActualCaller();

        // Transfer debt from violator to liquidator
        // Liquidator pays off violator's debt
        require(borrows[violator] >= repayAssets, "Repay exceeds violator debt");

        // Transfer assets from liquidator to cover the debt
        IERC20(asset()).transferFrom(liquidator, address(this), repayAssets);

        // Reduce violator's debt
        borrows[violator] -= repayAssets;

        // If flag is set, add extra debt to violator to break health invariant
        if (shouldLiquidateHealthyAccount) {
            // Add massive debt to make the violator unhealthy (10x the repayment)
            borrows[violator] += repayAssets * 10;
            totalBorrows += repayAssets * 10;
        }

        // Calculate collateral to seize (simplified: 1.1x repayment for liquidation bonus)
        uint256 collateralShares = (repayAssets * 110) / 100;
        require(collateralShares >= minYieldBalance, "Insufficient yield");

        // Transfer collateral shares from violator to liquidator
        // This would normally call the collateral vault's transfer
        try MockEVault(collateral).transferFrom(violator, liquidator, collateralShares) {
            // Successful collateral transfer
        } catch {
            // If external transfer fails, try internal transfer (if this vault is collateral)
            if (collateral == address(this)) {
                _transfer(violator, liquidator, collateralShares);
            }
        }

        // Update cash
        cash += repayAssets;

        emit Liquidation(liquidator, violator, collateral, repayAssets, collateralShares);
    }

    // ========================================
    // EVENTS
    // ========================================

    event Borrow(address indexed account, uint256 assets);
    event Repay(address indexed account, uint256 assets);
    event Liquidation(
        address indexed liquidator,
        address indexed violator,
        address indexed collateral,
        uint256 repayAssets,
        uint256 collateralShares
    );
}
