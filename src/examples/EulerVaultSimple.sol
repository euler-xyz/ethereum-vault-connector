// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "solmate/mixins/ERC4626.sol";
import "solmate/utils/SafeTransferLib.sol";
import "./EulerVaultBase.sol";

contract EulerVaultSimple is EulerVaultBase, ERC4626 {
    using SafeTransferLib for ERC20;

    event OwnershipTransferred(address indexed user, address indexed newOwner);
    event SupplyCapSet(uint newSupplyCap);

    uint public supplyCap;
    address public vaultOwner;
    
    constructor(
        address _eulerConductor, 
        ERC20 _asset, 
        string memory _name, 
        string memory _symbol
    ) EulerVaultBase(_eulerConductor) ERC4626(_asset, _name, _symbol) {
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

    function checkAccountStatusInternal(address, address[] calldata) internal view virtual override
    returns (bool isValid) {
        isValid = false;
        revert("NOT_BORROWABLE");
    }

    function vaultStatusHook(bool initialCall, bytes memory data) public view virtual override
    returns (bytes memory result) {
        if (initialCall) {
            // make i.e. a supply snapshot here and return it: 
            return abi.encode(convertToAssets(totalSupply));
        } else {
            // validate the vault state here, i.e.:
            uint initialSupply = abi.decode(data, (uint));
            uint finalSupply = convertToAssets(totalSupply);

            // i.e. supply cap can be implemented like this
            if (
                supplyCap != 0 && 
                finalSupply > supplyCap && 
                finalSupply > initialSupply
            ) revert VaultStatusHookViolation("supply cap exceeded");

            // i.e. if 90% of the assets were withdrawn, revert the transaction
            if (finalSupply < initialSupply / 10) revert VaultStatusHookViolation("withdrawal too large");
        }

        return "";
    }

    function disableController(address account) external virtual override 
    nonReentrant {
        IEulerConductor(eulerConductor).disableController(account, address(this));
    }

    function approve(address spender, uint256 amount) public override 
    returns (bool) {
        address owner = msg.sender;

        if (msg.sender == eulerConductor) {
            (, owner) = IEulerConductor(eulerConductor).getExecutionContext();
        }

        allowance[owner][spender] = amount;

        emit Approval(owner, spender, amount);

        return true;
    }

    function transfer(address to, uint256 amount) public override
    returns (bool) {
        return transferFrom(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public override 
    nonReentrant
    returns (bool) {
        ConductorContext memory context = conductorAuthenticate(from, false);

        if (!context.conductorCalling && msg.sender != from) {
            uint256 allowed = allowance[from][msg.sender]; // Saves gas for limited approvals.

            if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
        }
        
        balanceOf[from] -= amount;

        unchecked { balanceOf[to] += amount; }

        emit Transfer(from, to, amount);

        accountStatusCheck(from, context);
        accountStatusCheck(to, context);

        return true;
    }

    function deposit(uint256 assets, address receiver) public override
    returns (uint256 shares) {
        shares = deposit(assets, msg.sender, receiver);
    }

    function deposit(uint256 assets, address receiver, address owner) public
    returns (uint256 shares) {
        // Check for rounding error since we round down in previewDeposit.
        require((shares = previewDeposit(assets)) != 0, "ZERO_SHARES");
        mintInternal(shares, receiver, owner);
    }

    function mint(uint256 shares, address receiver) public override
    returns (uint256 assets) {
        assets = mint(shares, receiver, msg.sender);
    }

    function mint(uint256 shares, address receiver, address owner) public
    returns (uint256 assets) {
        assets = mintInternal(shares, receiver, owner);
    }

    function withdraw(uint256 assets, address receiver, address owner) public override
    returns (uint256 shares) {
        shares = previewWithdraw(assets); // No need to check for rounding error, previewWithdraw rounds up.
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

    function mintInternal(uint256 shares, address receiver, address owner) internal virtual 
    nonReentrant
    returns (uint256 assets) {
        ConductorContext memory context = conductorContext();
        preVaultStatusCheck(context);

        assets = previewMint(shares); // No need to check for rounding error, previewMint rounds up.

        // Need to transfer before minting or ERC777s could reenter.
        asset.safeTransferFrom(owner, address(this), assets);

        _mint(receiver, shares);

        // TODO figure out what to do with caller
        emit Deposit(msg.sender, receiver, assets, shares);

        afterDeposit(assets, shares);

        accountStatusCheck(receiver, context);
        postVaultStatusCheck(context);
    }

    function burnInternal(uint256 shares, address receiver, address owner) internal virtual 
    nonReentrant
    returns (uint256 assets) {
        ConductorContext memory context = conductorAuthenticate(owner, false);
        preVaultStatusCheck(context);

        if (
            !context.conductorCalling && 
            msg.sender != owner && 
            msg.sender != vaultOwner && // allows withdrawing reserves by the vault owner
            owner != address(this) // allows withdrawing reserves by the vault owner
        ) {
            uint256 allowed = allowance[owner][msg.sender]; // Saves gas for limited approvals.

            if (allowed != type(uint256).max) allowance[owner][msg.sender] = allowed - shares;
        }

        // Check for rounding error since we round down in previewRedeem.
        require((assets = previewRedeem(shares)) != 0, "ZERO_ASSETS");

        beforeWithdraw(assets, shares);

        _burn(owner, shares);

        // TODO figure out what to do with caller
        emit Withdraw(msg.sender, receiver, owner, assets, shares);

        asset.safeTransfer(receiver, assets);

        accountStatusCheck(owner, context);
        postVaultStatusCheck(context);
    }

    function donateInternal(uint256 shares, address owner) internal virtual 
    nonReentrant
    returns (uint256 assets) {
        ConductorContext memory context = conductorAuthenticate(owner, false);

        if (!context.conductorCalling && msg.sender != owner) {
            uint256 allowed = allowance[owner][msg.sender]; // Saves gas for limited approvals.

            if (allowed != type(uint256).max) allowance[owner][msg.sender] = allowed - shares;
        }

        // Check for rounding error since we round down in previewRedeem.
        require((assets = previewRedeem(shares)) != 0, "ZERO_ASSETS");

        beforeWithdraw(assets, shares);

        _burn(owner, shares);

        // TODO figure out what to do with caller
        emit Withdraw(msg.sender, address(this), owner, assets, shares);

        _mint(address(this), shares);

        // TODO figure out what to do with caller
        emit Deposit(address(this), address(this), assets, shares);

        afterDeposit(assets, shares);

        accountStatusCheck(owner, context);
    }

    function totalAssets() public view override returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function beforeWithdraw(uint256, uint256) internal override {}
    function afterDeposit(uint256, uint256) internal override {}
}
