// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../BaseLogic.sol";
import "../interfaces/IERC20Permit.sol";


/// @notice Definition of callback method that deferLiquidityCheck will invoke on your contract
interface IDeferredLiquidityCheck {
    function onDeferredLiquidityCheck(bytes memory data) external;
}


/// @notice Batch executions, liquidity check deferrals, and interfaces to fetch prices and account liquidity
contract Exec is BaseLogic {
    constructor(bytes32 moduleGitCommit_) BaseLogic(MODULEID__EXEC, moduleGitCommit_) {}

    /// @notice Single item in a batch request
    struct EulerBatchItem {
        bool allowError;
        address proxyAddr;
        bytes data;
    }

    /// @notice Single item in a batch response
    struct EulerBatchItemResponse {
        bool success;
        bytes result;
    }

    /// @notice Error containing results of a simulated batch dispatch
    error BatchDispatchSimulation(EulerBatchItemResponse[] simulation);


    // Simple entry points

    /// @notice Updates interest accumulator and totalBorrows, credits reserves, re-targets interest rate, and logs asset status
    /// @param market Address of a market
    function touch(address market) external nonReentrant liquidityCheck(address(0), 0) {
        doTouch(market);
    }

    /// @notice Transfer underlying tokens from sender to the Euler pool, and increase account's eTokens
    /// @param market Address of a market
    /// @param subAccountId 0 for primary, 1-255 for a sub-account
    /// @param amount In underlying units (use max uint256 for full underlying token balance)
    function deposit(address market, uint subAccountId, uint amount) external {
        deposit(market, unpackTrailingParamMsgSender(), subAccountId, amount);
    }

    /// @notice Transfer underlying tokens from Euler pool to sender, and decrease account's eTokens
    /// @param market Address of a market
    /// @param subAccountId 0 for primary, 1-255 for a sub-account
    /// @param amount In underlying units (use max uint256 for full pool balance)
    function withdraw(address market, uint subAccountId, uint amount) external {
        withdraw(market, unpackTrailingParamMsgSender(), subAccountId, amount);
    }

    /// @notice Transfer underlying tokens from the Euler pool to the sender, and increase sender's dTokens
    /// @param market Address of a market
    /// @param subAccountId 0 for primary, 1-255 for a sub-account
    /// @param amount In underlying units (use max uint256 for all available tokens)
    function borrow(address market, uint subAccountId, uint amount) external {
        borrow(market, unpackTrailingParamMsgSender(), subAccountId, amount);
    }

    /// @notice Transfer underlying tokens from the sender to the Euler pool, and decrease sender's dTokens
    /// @param market Address of a market
    /// @param subAccountId 0 for primary, 1-255 for a sub-account
    /// @param amount In underlying units (use max uint256 for full debt owed)
    function repay(address market, uint subAccountId, uint amount) external {
        repay(market, unpackTrailingParamMsgSender(), subAccountId, amount);
    }

    /// @notice Mint eTokens and a corresponding amount of dTokens ("self-borrow")
    /// @param market Address of a market
    /// @param subAccountId 0 for primary, 1-255 for a sub-account
    /// @param amount In underlying units
    function depositAndBorrow(address market, uint subAccountId, uint amount) external {
        depositAndBorrow(market, unpackTrailingParamMsgSender(), subAccountId, amount);
    }

    /// @notice Pay off dToken liability with eTokens ("self-repay")
    /// @param market Address of a market
    /// @param subAccountId 0 for primary, 1-255 for a sub-account
    /// @param amount In underlying units (use max uint256 to repay the debt in full or up to the available underlying balance)
    function repayAndWithdraw(address market, uint subAccountId, uint amount) external {
        repayAndWithdraw(market, unpackTrailingParamMsgSender(), subAccountId, amount);
    }

    function deposit(address market, address primary, uint subAccountId, uint amount) public nonReentrant marketStatusCheck(market) liquidityCheck(primary, subAccountId) {
        doDeposit(market, primary, subAccountId, amount, unpackTrailingParamMsgSender());
    }

    function withdraw(address market, address primary, uint subAccountId, uint amount) public nonReentrant accountOperatorOnly(primary, subAccountId) marketStatusCheck(market) liquidityCheck(primary, subAccountId) {
        doWithdraw(market, primary, subAccountId, amount);
    }

    function borrow(address market, address primary, uint subAccountId, uint amount) public nonReentrant accountOperatorOnly(primary, subAccountId) marketStatusCheck(market) liquidityCheck(primary, subAccountId) {
        doBorrow(market, primary, subAccountId, amount);
    }

    function repay(address market, address primary, uint subAccountId, uint amount) public nonReentrant marketStatusCheck(market) liquidityCheck(primary, subAccountId) {
        doRepay(market, primary, subAccountId, amount);
    }

    function depositAndBorrow(address market, address primary, uint subAccountId, uint amount) public nonReentrant accountOperatorOnly(primary, subAccountId) liquidityCheck(primary, subAccountId) {
        doDepositAndBorrow(market, primary, subAccountId, amount);
    }

    function repayAndWithdraw(address market, address primary, uint subAccountId, uint amount) public nonReentrant accountOperatorOnly(primary, subAccountId) liquidityCheck(primary, subAccountId) {
        doRepayAndWithdraw(market, primary, subAccountId, amount);
    }

    // for ERC4626 market compatibility
    function depositViaMarket(address market, address receiver, uint amount, address msgSender) external nonReentrant marketOnly(market) marketStatusCheck(market) liquidityCheck(receiver, 0) {
        doDeposit(market, receiver, 0, amount, msgSender);
    }
    
    function withdrawViaMarket(address market, address owner, uint amount) external nonReentrant marketOnly(market) marketStatusCheck(market) liquidityCheck(owner, 0) {
        doWithdraw(market, owner, 0, amount);
    }

    /// @notice Request a flash-loan. A onFlashLoan() callback in msg.sender will be invoked, which must repay the loan to the main Euler address prior to returning.
    /// @param market Address of a market
    /// @param amount In underlying units
    /// @param data Passed through to the onFlashLoan() callback, so contracts don't need to store transient data in storage
    function flashLoan(address market, uint amount, bytes calldata data) external nonReentrant liquidityCheck(address(0), 0) {
        IEulerMarket(market).flashLoan(unpackTrailingParamMsgSender(), amount, data);
    }


    // Add/remove collateral markets

    /// @notice Enable a market to become collateral, or do nothing if already enabled
    /// @param subAccountId 0 for primary, 1-255 for a sub-account
    /// @param market Address of a market
    function enableCollateralMarket(address market, uint subAccountId) external {
        enableCollateralMarket(market, unpackTrailingParamMsgSender(), subAccountId);
    }

    /// @notice Disable a market not to be collateral anymore, or do nothing if not already disabled
    /// @param subAccountId 0 for primary, 1-255 for a sub-account
    /// @param market Address of a market
    function disableCollateralMarket(address market, uint subAccountId) external {
        disableCollateralMarket(market, unpackTrailingParamMsgSender(), subAccountId);
    }

    function enableCollateralMarket(address market, address primary, uint subAccountId) public nonReentrant accountOperatorOnly(primary, subAccountId) liquidityCheck(primary, subAccountId) {
        require(marketLookup[market].isActive, "e/market-not-activated");
        doAddCollateralMarket(getSubAccount(primary, subAccountId), market);
    }

    function disableCollateralMarket(address market, address primary, uint subAccountId) public nonReentrant accountOperatorOnly(primary, subAccountId) liquidityCheck(primary, subAccountId) {
        doRemoveCollateralMarket(getSubAccount(primary, subAccountId), market);
    }


    // Check liquidity

    function checkLiquidity(address primary, uint subAccountId) external view {
        checkLiquidity(getSubAccount(primary, subAccountId));
    }

    function checkLiquidity(address account) public view {
        checkLiquidityInternal(account);
    }


    // Custom execution methods

    /// @notice Defer liquidity checking for an account, to perform rebalancing, flash loans, etc. msg.sender must implement IDeferredLiquidityCheck
    /// @param data Passed through to the onDeferredLiquidityCheck() callback, so contracts don't need to store transient data in storage
    function deferLiquidityCheck(bytes memory data) external reentrantBatch {
        address msgSender = unpackTrailingParamMsgSender();

        IDeferredLiquidityCheck(msgSender).onDeferredLiquidityCheck(data);
    }

    /// @notice Execute several operations in a single transaction
    /// @param items List of operations to execute
    function batchDispatch(EulerBatchItem[] calldata items) external reentrantBatch {
        doBatchDispatch(items, false);
    }

    /// @notice Call batch dispatch, but instruct it to revert with the responses, before the liquidity checks.
    /// @param items List of operations to execute
    /// @dev During simulation all batch items are executed, regardless of the `allowError` flag
    function batchDispatchSimulate(EulerBatchItem[] calldata items) external reentrantBatch {
        doBatchDispatch(items, true);

        // TODO decide if really needed. commenting out for now to get rid of the warning
        //revert("e/batch/simulation-did-not-revert");
    }

    function doBatchDispatch(EulerBatchItem[] calldata items, bool revertResponse) private {
        address msgSender = unpackTrailingParamMsgSender();

        EulerBatchItemResponse[] memory response;
        if (revertResponse) response = new EulerBatchItemResponse[](items.length);

        for (uint i = 0; i < items.length;) {
            EulerBatchItem calldata item = items[i];
            address proxyAddr = item.proxyAddr;

            uint32 calledModuleId = trustedSenders[proxyAddr].moduleId;
            address calledModuleImpl = trustedSenders[proxyAddr].moduleImpl;
            bytes memory inputWrapped = abi.encodePacked(item.data, uint160(msgSender), uint160(proxyAddr));

            (bool success, bytes memory result) = calledModuleId == 0 
                ? proxyAddr.call(inputWrapped)
                : calledModuleImpl.delegatecall(inputWrapped);

            if (revertResponse) {
                EulerBatchItemResponse memory r = response[i];
                r.success = success;
                r.result = result;
            } else if (!(success || item.allowError)) {
                revertBytes(result);
            }

            unchecked { ++i; }
        }

        if (revertResponse) revert BatchDispatchSimulation(response);
    }


    /// @notice Apply EIP2612 signed permit on a target token from sender to euler contract
    /// @param token Token address
    /// @param value Allowance value
    /// @param deadline Permit expiry timestamp
    /// @param v secp256k1 signature v
    /// @param r secp256k1 signature r
    /// @param s secp256k1 signature s
    function usePermit(address token, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external nonReentrant {
        address msgSender = unpackTrailingParamMsgSender();

        IERC20Permit(token).permit(msgSender, address(this), value, deadline, v, r, s);
    }

    /// @notice Apply DAI like (allowed) signed permit on a target token from sender to euler contract
    /// @param token Token address
    /// @param nonce Sender nonce
    /// @param expiry Permit expiry timestamp
    /// @param allowed If true, set unlimited allowance, otherwise set zero allowance
    /// @param v secp256k1 signature v
    /// @param r secp256k1 signature r
    /// @param s secp256k1 signature s
    function usePermitAllowed(address token, uint256 nonce, uint256 expiry, bool allowed, uint8 v, bytes32 r, bytes32 s) external nonReentrant {
        address msgSender = unpackTrailingParamMsgSender();

        IERC20Permit(token).permit(msgSender, address(this), nonce, expiry, allowed, v, r, s);
    }

    /// @notice Apply allowance to tokens expecting the signature packed in a single bytes param
    /// @param token Token address
    /// @param value Allowance value
    /// @param deadline Permit expiry timestamp
    /// @param signature secp256k1 signature encoded as rsv
    function usePermitPacked(address token, uint256 value, uint256 deadline, bytes calldata signature) external nonReentrant {
        address msgSender = unpackTrailingParamMsgSender();

        IERC20Permit(token).permit(msgSender, address(this), value, deadline, signature);
    }

    /// @notice Execute a staticcall to an arbitrary address with an arbitrary payload.
    /// @param contractAddress Address of the contract to call
    /// @param payload Encoded call payload
    /// @return result Encoded return data
    /// @dev Intended to be used in static-called batches, to e.g. provide detailed information about the impacts of the simulated operation.
    function doStaticCall(address contractAddress, bytes memory payload) external view returns (bytes memory) {
        (bool success, bytes memory result) = contractAddress.staticcall(payload);
        if (!success) revertBytes(result);

        assembly {
            return(add(32, result), mload(result))
        }
    }
}
