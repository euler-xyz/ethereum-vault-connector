// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "solmate/mixins/ERC4626.sol";
import "solmate/utils/SafeTransferLib.sol";
import "./CreditVaultBase.sol";

contract CreditVaultSimple is CreditVaultBase, ERC4626 {
    using SafeTransferLib for ERC20;

    event OwnershipTransferred(address indexed user, address indexed newOwner);
    event SupplyCapSet(uint newSupplyCap);

    uint public supplyCap;
    address public vaultOwner;
    
    constructor(
        ICVP _cvp, 
        ERC20 _asset, 
        string memory _name, 
        string memory _symbol
    ) CreditVaultBase(_cvp) ERC4626(_asset, _name, _symbol) {
        vaultOwner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    modifier onlyOwner() {
        if (msg.sender != vaultOwner) revert NotAuthorized();
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        vaultOwner = newOwner;
        emit OwnershipTransferred(msg.sender, newOwner);
    }

    function setSupplyCap(uint newSupplyCap) external onlyOwner {
        supplyCap = newSupplyCap;
        emit SupplyCapSet(newSupplyCap);
    }

    function doVaultStatusSnapshot() internal view virtual override returns (bytes memory snapshot) {
        // make i.e. a supply snapshot here and return it: 
        snapshot = abi.encode(convertToAssets(totalSupply));
    }

    function doCheckVaultStatus(bytes memory snapshot) internal virtual override returns (bool isValid, bytes memory data) {
        isValid = true;

        // validate the vault state here, i.e.:
        uint initialSupply = abi.decode(snapshot, (uint));
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

        // i.e. if 90% of the assets were withdrawn, revert the transaction
        //if (finalSupply < initialSupply / 10) {
        //    isValid = false;
        //    data = "withdrawal too large";
        //}
    }

    function doCheckAccountStatus(address, address[] calldata) internal view virtual override
    returns (bool isValid, bytes memory data) {
        isValid = true;
        data = "";
    }

    function disableController(address account) external virtual override 
    nonReentrant {
        cvp.disableController(account);
    }

    function approve(address spender, uint256 amount) public override 
    returns (bool) {
        address msgSender = CVPAuthenticate(msg.sender, false);

        allowance[msgSender][spender] = amount;

        emit Approval(msgSender, spender, amount);

        return true;
    }

    function transfer(address to, uint256 amount) public override
    returns (bool) {
        return transferFrom(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public override 
    nonReentrant
    returns (bool) {
        address msgSender = CVPAuthenticate(msg.sender, false);

        if (msgSender != from) {
            uint256 allowed = allowance[from][msgSender];

            if (allowed != type(uint256).max) allowance[from][msgSender] = allowed - amount;
        }
        
        balanceOf[from] -= amount;

        unchecked { balanceOf[to] += amount; }

        emit Transfer(from, to, amount);

        address[] memory accounts = new address[](2);
        accounts[0] = from;
        accounts[1] = to;
        requireAccountsStatusCheck(accounts);

        return true;
    }

    function deposit(uint256 assets, address receiver) public override
    returns (uint256 shares) {
        shares = previewDeposit(assets);
        mintInternal(shares, receiver);
    }

    function mint(uint256 shares, address receiver) public override
    returns (uint256 assets) {
        assets = mintInternal(shares, receiver);
    }

    function withdraw(uint256 assets, address receiver, address owner) public override
    returns (uint256 shares) {
        shares = previewWithdraw(assets);
        burnInternal(shares, receiver, owner);
    }

    function redeem(uint256 shares, address receiver, address owner) public override 
    returns (uint256 assets) {
        assets = burnInternal(shares, receiver, owner);
    }

    function withdrawToReserves(uint256 assets, address owner) external 
    returns (uint256 shares) {
        shares = previewWithdraw(assets);
        donateInternal(shares, owner);
    }

    function redeemToReserves(uint256 shares, address owner) external 
    returns (uint256 assets) {
        assets = donateInternal(shares, owner);
    }

    function withdrawReserves(uint256 assets, address receiver) external 
    onlyOwner
    returns (uint256 shares) {
        shares = previewWithdraw(assets);
        burnInternal(shares, receiver, address(this));
    }

    function redeemReserves(uint256 shares, address receiver) external 
    onlyOwner
    returns (uint256 assets) {
        assets = burnInternal(shares, receiver, address(this));
    }

    function mintInternal(uint256 shares, address receiver) internal virtual 
    nonReentrant clearBytes
    returns (uint256 assets) {
        vaultStatusSnapshot();
        address msgSender = CVPAuthenticate(msg.sender, false);

        require(shares > 0, "ZERO_SHARES");

        assets = previewMint(shares); // No need to check for rounding error, previewMint rounds up.

        // Need to transfer before minting or ERC777s could reenter.
        asset.safeTransferFrom(msgSender, address(this), assets);

        _mint(receiver, shares);

        emit Deposit(msgSender, receiver, assets, shares);

        afterDeposit(assets, shares);

        requireAccountStatusCheck(receiver);
        requireVaultStatusCheck();
    }

    function burnInternal(uint256 shares, address receiver, address owner) internal virtual 
    nonReentrant clearBytes
    returns (uint256 assets) {
        vaultStatusSnapshot();
        address msgSender = CVPAuthenticate(msg.sender, false);

        if (
            msgSender != owner && 
            !(msgSender == vaultOwner && address(this) == owner) // allows withdrawing reserves by the vault owner
        ) {
            uint256 allowed = allowance[owner][msgSender];

            if (allowed != type(uint256).max) allowance[owner][msgSender] = allowed - shares;
        }

        // Check for rounding error since we round down in previewRedeem.
        require((assets = previewRedeem(shares)) != 0, "ZERO_ASSETS");

        beforeWithdraw(assets, shares);

        _burn(owner, shares);

        emit Withdraw(msgSender, receiver, owner, assets, shares);

        asset.safeTransfer(receiver, assets);

        requireAccountStatusCheck(owner);
        requireVaultStatusCheck();
    }

    function donateInternal(uint256 shares, address owner) internal virtual 
    nonReentrant
    returns (uint256 assets) {
        address msgSender = CVPAuthenticate(msg.sender, false);

        if (msgSender != owner) {
            uint256 allowed = allowance[owner][msgSender];

            if (allowed != type(uint256).max) allowance[owner][msgSender] = allowed - shares;
        }

        // Check for rounding error since we round down in previewRedeem.
        require((assets = previewRedeem(shares)) != 0, "ZERO_ASSETS");

        beforeWithdraw(assets, shares);

        _burn(owner, shares);

        emit Withdraw(msgSender, address(this), owner, assets, shares);

        _mint(address(this), shares);

        emit Deposit(msgSender, address(this), assets, shares);

        afterDeposit(assets, shares);

        requireAccountStatusCheck(owner);
    }

    function totalAssets() public view override returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function beforeWithdraw(uint256, uint256) internal override {}
    function afterDeposit(uint256, uint256) internal override {}
}
