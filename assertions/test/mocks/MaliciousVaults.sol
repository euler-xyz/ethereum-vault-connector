// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IEVC} from "../../../src/interfaces/IEthereumVaultConnector.sol";
import {MockEVault} from "./MockEVault.sol";
import {MockERC20} from "./MockERC20.sol";

/// @title CashThiefVault
/// @notice Malicious vault that steals cash without updating internal accounting
/// @dev Used for testing VaultAccountingIntegrityAssertion
contract CashThiefVault is MockEVault {
    // Behavior flags
    bool public stealOnWithdraw; // Transfers extra assets without updating cash
    bool public skipCashUpdate; // Skips cash updates on withdraw

    constructor(MockERC20 _asset, IEVC _evc) MockEVault(_asset, _evc) {}

    function setStealOnWithdraw(
        bool _enabled
    ) external {
        stealOnWithdraw = _enabled;
    }

    function setSkipCashUpdate(
        bool _enabled
    ) external {
        skipCashUpdate = _enabled;
    }

    /// @notice Corrupt cash value manually (for testing bad state)
    function corruptCash(
        uint256 newCash
    ) external {
        cash = newCash;
    }

    /// @notice Malicious withdraw - can steal or skip cash update
    function withdraw(uint256 assets, address receiver, address owner) public override returns (uint256) {
        address caller = _getActualCaller();
        uint256 shares = previewWithdraw(assets);
        _withdraw(caller, receiver, owner, assets, shares);

        // Update cash (unless skipCashUpdate flag is set)
        if (!skipCashUpdate) {
            cash -= assets;
        }

        // Steal extra assets if flag set
        if (stealOnWithdraw) {
            MockERC20(asset()).transfer(receiver, 10e18);
        }

        return shares;
    }
}

/// @title RateManipulatorVault
/// @notice Malicious vault that manipulates exchange rate during operations
/// @dev Used for testing VaultExchangeRateSpikeAssertion
contract RateManipulatorVault is MockEVault {
    uint256 public inflationBps; // Inflation to apply on next operation (in basis points)
    uint256 public deflationBps; // Deflation to apply on next operation (in basis points)

    constructor(MockERC20 _asset, IEVC _evc) MockEVault(_asset, _evc) {}

    /// @notice Set inflation to apply on next deposit
    /// @param bps Basis points to inflate (e.g., 500 = 5%)
    function setInflationBps(
        uint256 bps
    ) external {
        inflationBps = bps;
    }

    /// @notice Set deflation to apply on next deposit
    /// @param bps Basis points to deflate (e.g., 500 = 5%)
    function setDeflationBps(
        uint256 bps
    ) external {
        deflationBps = bps;
    }

    /// @notice Inflate totalAssets by percentage (for testing outside of transactions)
    /// @param percentage Percentage to inflate (e.g., 10 = 10%)
    function inflateTotalAssets(
        uint256 percentage
    ) external {
        uint256 current = totalAssets();
        uint256 inflation = (current * percentage) / 100;
        MockERC20(asset()).mint(address(this), inflation);
    }

    /// @notice Deflate totalAssets by percentage (for testing outside of transactions)
    /// @param percentage Percentage to deflate (e.g., 10 = 10%)
    function deflateTotalAssets(
        uint256 percentage
    ) external {
        uint256 current = totalAssets();
        uint256 deflation = (current * percentage) / 100;
        // Burn tokens to simulate loss
        MockERC20(asset()).transfer(address(0xdead), deflation);
    }

    /// @notice Override deposit to apply inflation or deflation DURING the operation
    function deposit(uint256 assets, address receiver) public override returns (uint256) {
        // Apply inflation if set (increases totalAssets before operation completes)
        if (inflationBps > 0) {
            uint256 current = totalAssets();
            uint256 inflation = (current * inflationBps) / 10000;
            MockERC20(asset()).mint(address(this), inflation);
            inflationBps = 0; // Reset after use
        }

        // Apply deflation if set (decreases totalAssets before operation completes)
        if (deflationBps > 0) {
            uint256 current = totalAssets();
            uint256 deflation = (current * deflationBps) / 10000;
            MockERC20(asset()).transfer(address(0xdead), deflation);
            deflationBps = 0; // Reset after use
        }

        return super.deposit(assets, receiver);
    }
}

/// @title MockNonVaultContract
/// @notice A contract that doesn't implement ERC4626 (simulates Permit2, routers, etc.)
/// @dev Used for testing that assertions gracefully handle non-vault contracts in batches
contract MockNonVaultContract {
    event SomethingDone(address sender);

    /// @notice A simple function that doesn't have anything to do with vaults
    function doSomething() external returns (bool) {
        emit SomethingDone(msg.sender);
        return true;
    }

    // Note: This contract intentionally does NOT have an asset() function
    // to test that assertions handle this gracefully
}

/// @title WrapperVault
/// @notice A wrapper vault that deposits into an underlying vault (like Tulipa ETH Earn -> EVK Vault)
/// @dev Used for testing nested vault deposit handling in assertions
contract WrapperVault is MockEVault {
    MockEVault public underlyingVault;

    constructor(IERC20 _asset, IEVC _evc, MockEVault _underlyingVault) MockEVault(_asset, _evc) {
        underlyingVault = _underlyingVault;
        // Approve underlying vault to spend our tokens
        _asset.approve(address(_underlyingVault), type(uint256).max);
    }

    /// @notice Override deposit to also deposit into underlying vault
    function deposit(uint256 assets, address receiver) public override returns (uint256) {
        // First, do the normal deposit (pull tokens from user, mint shares)
        uint256 shares = super.deposit(assets, receiver);

        // Then, deposit all received assets into underlying vault
        // This creates the nested vault pattern where:
        // 1. Transfer: user -> wrapperVault (not counted, from != vault)
        // 2. Transfer: wrapperVault -> underlyingVault (counted as totalTransferred)
        // 3. Deposit event from underlyingVault with sender=wrapperVault (counted as totalDepositedToUnderlying)
        underlyingVault.deposit(assets, address(this));

        return shares;
    }
}

/// @title EventManipulatorVault
/// @notice Malicious vault that transfers assets without emitting proper events
/// @dev Used for testing VaultAssetTransferAccountingAssertion
contract EventManipulatorVault is MockEVault {
    // Behavior flags
    bool public shouldSkipWithdrawEvent;
    bool public shouldSkipBorrowEvent;
    bool public shouldUnderreportAmount;
    bool public shouldMakeExtraTransfer;

    constructor(IERC20 _asset, IEVC _evc) MockEVault(_asset, _evc) {}

    function setShouldSkipWithdrawEvent(
        bool value
    ) external {
        shouldSkipWithdrawEvent = value;
    }

    function setShouldSkipBorrowEvent(
        bool value
    ) external {
        shouldSkipBorrowEvent = value;
    }

    function setShouldUnderreportAmount(
        bool value
    ) external {
        shouldUnderreportAmount = value;
    }

    function setShouldMakeExtraTransfer(
        bool value
    ) external {
        shouldMakeExtraTransfer = value;
    }

    /// @notice Override withdraw to optionally skip event or underreport
    function withdraw(uint256 assets, address receiver, address owner) public override returns (uint256) {
        address caller = _getActualCaller();
        uint256 shares = previewWithdraw(assets);

        // Make the actual transfer
        IERC20(asset()).transfer(receiver, assets);

        // Burn shares
        _burn(owner, shares);

        // Update cash
        cash -= assets;

        // Conditionally emit Withdraw event based on flags
        if (!shouldSkipWithdrawEvent) {
            if (shouldUnderreportAmount) {
                // Under-report: emit half the actual amount
                emit Withdraw(caller, receiver, owner, assets / 2, shares);
            } else {
                // Normal: emit correct amount
                emit Withdraw(caller, receiver, owner, assets, shares);
            }
        }
        // If shouldSkipWithdrawEvent, don't emit event at all

        // If flag is set, make extra unaccounted transfer
        if (shouldMakeExtraTransfer) {
            IERC20(asset()).transfer(receiver, 100e18);
        }

        return shares;
    }

    /// @notice Override borrow to optionally skip event
    function borrow(uint256 assets, address receiver) public override returns (uint256) {
        address caller = _getActualCaller();

        // Transfer assets
        IERC20(asset()).transfer(receiver, assets);
        cash -= assets;
        borrows[caller] += assets;
        totalBorrows += assets;

        // Skip Borrow event if flag is set
        if (shouldSkipBorrowEvent) {
            // Don't emit Borrow event - breaks invariant
            return assets;
        }

        emit Borrow(caller, assets);
        return assets;
    }
}
