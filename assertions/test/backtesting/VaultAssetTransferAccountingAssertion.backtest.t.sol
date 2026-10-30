// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {CredibleTestWithBacktesting} from "credible-std/CredibleTestWithBacktesting.sol";
import {BacktestingTypes} from "credible-std/utils/BacktestingTypes.sol";
import {VaultAssetTransferAccountingAssertion} from "../../src/VaultAssetTransferAccountingAssertion.a.sol";

/// @title VaultAssetTransferAccountingAssertion Backtesting
/// @notice Tests VaultAssetTransferAccountingAssertion against historical EVC transactions on mainnet
/// @dev Validates that all asset transfers are properly accounted for by Withdraw or Borrow events
contract VaultAssetTransferAccountingAssertionBacktest is CredibleTestWithBacktesting {
    // EVC mainnet deployment
    address constant EVC_MAINNET = 0x0C9a3dd6b8F28529d72d7f9cE918D493519EE383;

    address constant EVC_LINEA = 0xd8CeCEe9A04eA3d941a959F68fb4486f23271d09;

    // Mainnet Perspective addresses
    address constant MAINNET_GOVERNED_PERSPECTIVE = 0xcD7E3a18b23d60c3eD2cae736fe9c0Ad116a54a4;
    address constant MAINNET_ESCROWED_COLLATERAL_PERSPECTIVE = 0xc79C866dd9f2EF9E5Ee0C68bCEB84beC9D451044;

    // Linea Perspective addresses
    address constant LINEA_GOVERNED_PERSPECTIVE = 0x74f9fD22aA0Dd5Bbf6006a4c9818248eb476C50A;
    address constant LINEA_ESCROWED_COLLATERAL_PERSPECTIVE = 0xc8d904FE94b65612AED5A73203C0eF8f3A0308C0;

    // Block configuration
    uint256 constant END_BLOCK = 27419134;
    uint256 constant BLOCK_RANGE = 3;

    /// @notice Helper to get assertion creation code with mainnet perspectives
    function getMainnetAssertionCreationCode() internal pure returns (bytes memory) {
        address[] memory perspectives = new address[](2);
        perspectives[0] = MAINNET_GOVERNED_PERSPECTIVE;
        perspectives[1] = MAINNET_ESCROWED_COLLATERAL_PERSPECTIVE;
        return abi.encodePacked(type(VaultAssetTransferAccountingAssertion).creationCode, abi.encode(perspectives));
    }

    /// @notice Helper to get assertion creation code with Linea perspectives
    function getLineaAssertionCreationCode() internal pure returns (bytes memory) {
        address[] memory perspectives = new address[](2);
        perspectives[0] = LINEA_GOVERNED_PERSPECTIVE;
        perspectives[1] = LINEA_ESCROWED_COLLATERAL_PERSPECTIVE;
        return abi.encodePacked(type(VaultAssetTransferAccountingAssertion).creationCode, abi.encode(perspectives));
    }

    /// @notice Backtest batch operations against Linea EVC
    /// @dev Tests that all asset transfers are accounted for in batch operations
    function testBacktest_VaultAssetTransferAccounting_BatchOperations() public {
        BacktestingTypes.BacktestingResults memory results = executeBacktest(
            BacktestingTypes.BacktestingConfig({
                targetContract: EVC_LINEA,
                endBlock: END_BLOCK,
                blockRange: BLOCK_RANGE,
                assertionCreationCode: getLineaAssertionCreationCode(),
                assertionSelector: VaultAssetTransferAccountingAssertion.assertionBatchAssetTransferAccounting.selector,
                rpcUrl: vm.envString("MAINNET_RPC_URL"),
                detailedBlocks: false,
                forkByTxHash: true
            })
        );

        // Verify no assertion failures in historical data
        assertEq(results.assertionFailures, 0, "Should not detect violations in healthy protocol");
    }

    /// @notice Backtest single call operations against mainnet EVC
    /// @dev Tests that all asset transfers are accounted for in call operations
    function testBacktest_VaultAssetTransferAccounting_CallOperations() public {
        BacktestingTypes.BacktestingResults memory results = executeBacktest(
            BacktestingTypes.BacktestingConfig({
                targetContract: EVC_MAINNET,
                endBlock: END_BLOCK,
                blockRange: BLOCK_RANGE,
                assertionCreationCode: getMainnetAssertionCreationCode(),
                assertionSelector: VaultAssetTransferAccountingAssertion.assertionCallAssetTransferAccounting.selector,
                rpcUrl: vm.envString("MAINNET_RPC_URL"),
                detailedBlocks: false,
                forkByTxHash: true
            })
        );

        assertEq(results.assertionFailures, 0, "Should not detect violations in healthy protocol");
    }

    /// @notice Backtest control collateral operations against mainnet EVC
    /// @dev Tests that all asset transfers are accounted for in controlCollateral operations
    function testBacktest_VaultAssetTransferAccounting_ControlCollateralOperations() public {
        BacktestingTypes.BacktestingResults memory results = executeBacktest(
            BacktestingTypes.BacktestingConfig({
                targetContract: EVC_MAINNET,
                endBlock: END_BLOCK,
                blockRange: BLOCK_RANGE,
                assertionCreationCode: getMainnetAssertionCreationCode(),
                assertionSelector: VaultAssetTransferAccountingAssertion.assertionControlCollateralAssetTransferAccounting
                    .selector,
                rpcUrl: vm.envString("MAINNET_RPC_URL"),
                detailedBlocks: false,
                forkByTxHash: true
            })
        );

        assertEq(results.assertionFailures, 0, "Should not detect violations in healthy protocol");
    }

    /// @notice Single transaction backtest for VaultAssetTransferAccountingAssertion on Linea
    /// @dev Tests the batch asset transfer accounting assertion against a specific transaction
    function testBacktest_singleTx_lineaMainnet_VaultAssetTransferAccountingAssertion() public {
        // Use LINEA_RPC_URL if available, fallback to MAINNET_RPC_URL for local testing
        string memory rpcUrl;
        try vm.envString("LINEA_RPC_URL") returns (string memory url) {
            rpcUrl = url;
        } catch {
            rpcUrl = vm.envString("MAINNET_RPC_URL");
        }

        BacktestingTypes.BacktestingResults memory results = executeBacktestForTransaction(
            0xf2f84d5a619a1645f5530ae61613be751f277b6571e81e75c4a751c6cb1753ac,
            EVC_LINEA,
            getLineaAssertionCreationCode(),
            VaultAssetTransferAccountingAssertion.assertionBatchAssetTransferAccounting.selector,
            rpcUrl
        );

        assertEq(results.assertionFailures, 0, "Single tx backtest should pass");
    }
}
