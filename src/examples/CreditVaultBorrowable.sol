// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "solmate/utils/SafeTransferLib.sol";
import "./CreditVaultSimple.sol";

/// @notice Definition of callback method that flashLoan will invoke on your contract
interface IFlashLoan {
    function onFlashLoan(bytes memory data) external;
}

contract CreditVaultBorrowable is CreditVaultSimple {
    using SafeTransferLib for ERC20;
    
    event BorrowCapSet(uint newBorrowCap);
    event Borrow(address indexed caller, address indexed owner, uint256 assets);
    event Repay(address indexed caller, address indexed receiver, address indexed owner, uint256 assets);

    error FlashloanNotRepaid();

    uint public borrowCap;
    uint public totalBorrowed;
    mapping(address => uint) public owed;
    
    constructor(
        ICVP _cvp, 
        ERC20 _asset, 
        string memory _name, 
        string memory _symbol
    ) CreditVaultSimple(_cvp, _asset, _name, _symbol) {}

    function setBorrowCap(uint newBorrowCap) external onlyOwner {
        borrowCap = newBorrowCap;
        emit BorrowCapSet(newBorrowCap);
    }

    function doVaultStatusSnapshot() internal view override returns (bytes memory snapshot) {
        snapshot = abi.encode(
            convertToAssets(totalSupply),
            totalBorrowed
        );
    }

    function doCheckVaultStatus(bytes memory snapshot) internal virtual override returns (bool isValid, bytes memory data) {
        isValid = true;

        // validate the vault state here, i.e.:
        (uint initialSupply, uint initialBorrows) = abi.decode(snapshot, (uint, uint));
        uint finalSupply = convertToAssets(totalSupply);

        // i.e. supply cap can be implemented like this
        if (
            supplyCap != 0 && 
            finalSupply > supplyCap && 
            finalSupply > initialSupply
        ) {
            isValid = false;
            data = "supply cap exceeded";
        }

        // or borrow cap can be implemented like this
        if (
            borrowCap != 0 && 
            totalBorrowed > borrowCap &&
            totalBorrowed > initialBorrows
        ) {
            isValid = false;
            data = "borrow cap exceeded";
        }

        // i.e. if 90% of the assets were withdrawn, revert the transaction
        //if (finalSupply < initialSupply / 10) {
        //    isValid = false;
        //    data = "withdrawal too large";
        //}
    }

    function doCheckAccountStatus(address account, address[] calldata collaterals) internal view override
    returns (bool isValid, bytes memory data) {
        isValid = true;

        if (owed[account] == 0) return (isValid, data);

        // TODO: here the risk manager should be plugged in that checks if the account is still solvent
        // based on the amount borrowed, amount of collaterals provided, borrow factors, collateral 
        // factors and asset prices

        // in this example, let's say that it's only possible to borrow against the same asset
        // up to 90% of it's value
        for (uint i = 0; i < collaterals.length;) {
            if (collaterals[i] == address(asset)) {
                uint collateral = convertToAssets(balanceOf[account]);
                uint borrowable = collateral * 9 / 10;

                if (owed[account] > borrowable) {
                    isValid = false;
                    data = "collateral violation";
                }

                break;
            }
            unchecked { ++i; }
        }
    }

    function disableController(address account) external override nonReentrant {
        if (owed[account] == 0) cvp.disableController(account);
    }

    function flashLoan(uint256 amount, bytes calldata data) external nonReentrant {
        uint origBalance = asset.balanceOf(address(this));

        asset.safeTransfer(msg.sender, amount);

        IFlashLoan(msg.sender).onFlashLoan(data);

        if (asset.balanceOf(address(this)) < origBalance) revert FlashloanNotRepaid();
    }

    function borrow(uint256 assets, address receiver, address owner) external virtual {
        borrowInternal(assets, receiver, owner);
    }

    function repay(uint256 assets, address receiver) external virtual {
        repay(assets, receiver, msg.sender);
    }

    function repay(uint256 assets, address receiver, address owner) public virtual {
        repayInternal(assets, receiver, owner);
    }

    function wind(uint256 assets, address receiver) external virtual 
    returns (uint shares) {
        shares= windInternal(assets, receiver);
    }

    function unwind(uint256 assets, address receiver) external virtual 
    returns (uint shares) {
        shares= unwindInternal(assets, receiver);
    }

    function transferDebt(address from, address to, uint256 amount) external virtual 
    returns (bool) {
        transferDebtInternal(from, to, amount);
        return true;
    }

    function borrowInternal(uint256 assets, address receiver, address owner) internal virtual 
    nonReentrant {
        CVPAuthenticate(msg.sender, owner, true);
        vaultStatusSnapshot();
        
        if (msg.sender != address(cvp) && msg.sender != owner) revert NotAuthorized();

        asset.safeTransfer(receiver, assets);

        totalBorrowed += assets;

        unchecked { owed[owner] += assets; }

        emit Borrow(msg.sender, owner, assets);

        requireAccountStatusCheck(owner);
        requireVaultStatusCheck();
    }

    function repayInternal(uint256 assets, address receiver, address owner) internal virtual 
    nonReentrant {
        vaultStatusSnapshot();
        
        asset.safeTransferFrom(owner, address(this), assets);

        owed[owner] -= assets;

        unchecked { totalBorrowed -= assets; }

        emit Repay(msg.sender, receiver, owner, assets);

        if (owed[receiver] == 0) cvp.disableController(receiver);

        requireAccountStatusCheck(receiver);
        requireVaultStatusCheck();
    }

    function windInternal(uint256 assets, address receiver) internal virtual 
    nonReentrant
    returns (uint shares) {
        CVPAuthenticate(msg.sender, receiver, true);

        if (msg.sender != address(cvp) && msg.sender != receiver) revert NotAuthorized();
        
        require((shares = previewDeposit(assets)) != 0, "ZERO_SHARES");
        assets = previewMint(shares);

        _mint(receiver, shares);

        totalBorrowed += assets;

        unchecked { owed[receiver] += assets; }

        emit Deposit(msg.sender, receiver, assets, shares);
        emit Borrow(msg.sender, receiver, assets);

        requireAccountStatusCheck(receiver);
    }

    function unwindInternal(uint256 assets, address receiver) internal virtual 
    nonReentrant
    returns (uint shares) {
        CVPAuthenticate(msg.sender, receiver, true);
        
        if (msg.sender != address(cvp) && msg.sender != receiver) revert NotAuthorized();
        
        shares = previewWithdraw(assets);
        require((assets = previewRedeem(shares)) != 0, "ZERO_ASSETS");

        owed[receiver] -= assets;    

        unchecked { totalBorrowed -= assets; }

        emit Repay(msg.sender, receiver, receiver, assets);

        _burn(receiver, shares);
        emit Withdraw(msg.sender, receiver, receiver, assets, shares);

        if (owed[receiver] == 0) cvp.disableController(receiver);

        requireAccountStatusCheck(receiver);
    }

    function transferDebtInternal(address from, address to, uint256 amount) internal virtual 
    nonReentrant {
        CVPAuthenticate(msg.sender, to, true);
        
        if (msg.sender != address(cvp) && msg.sender != to) revert NotAuthorized();
        
        owed[from] -= amount;    

        unchecked { owed[to] += amount; }

        emit Repay(msg.sender, from, to, amount);
        emit Borrow(msg.sender, to, amount);

        if (owed[from] == 0) cvp.disableController(from);
        
        address[] memory accounts = new address[](2);
        accounts[0] = from;
        accounts[1] = to;
        requireAccountsStatusCheck(accounts);
    }
}
