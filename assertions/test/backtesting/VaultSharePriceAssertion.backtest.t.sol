// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {CredibleTestWithBacktesting} from "credible-std/CredibleTestWithBacktesting.sol";
import {BacktestingTypes} from "credible-std/utils/BacktestingTypes.sol";
import {VaultSharePriceAssertion} from "../../src/VaultSharePriceAssertion.a.sol";

/// @title VaultSharePriceAssertion Backtesting
/// @notice Tests VaultSharePriceAssertion against historical EVC transactions
/// @dev Update the block range constants to test different historical periods
contract VaultSharePriceAssertionBacktest is CredibleTestWithBacktesting {
    // EVC mainnet deployment
    address constant EVC_MAINNET = 0x0C9a3dd6b8F28529d72d7f9cE918D493519EE383;

    // EVC Linea deployment
    address constant EVC_LINEA = 0xd8CeCEe9A04eA3d941a959F68fb4486f23271d09;

    // Mainnet Perspective addresses
    address constant MAINNET_GOVERNED_PERSPECTIVE = 0xcD7E3a18b23d60c3eD2cae736fe9c0Ad116a54a4;
    address constant MAINNET_ESCROWED_COLLATERAL_PERSPECTIVE = 0xc79C866dd9f2EF9E5Ee0C68bCEB84beC9D451044;

    // Linea Perspective addresses
    address constant LINEA_GOVERNED_PERSPECTIVE = 0x74f9fD22aA0Dd5Bbf6006a4c9818248eb476C50A;
    address constant LINEA_ESCROWED_COLLATERAL_PERSPECTIVE = 0xc8d904FE94b65612AED5A73203C0eF8f3A0308C0;

    // Block configuration for mainnet - adjust these to test different ranges
    uint256 constant MAINNET_END_BLOCK = 21551000;
    uint256 constant MAINNET_BLOCK_RANGE = 3;

    // Block configuration for Linea - adjust these to test different ranges
    uint256 constant LINEA_END_BLOCK = 27419134;
    uint256 constant LINEA_BLOCK_RANGE = 1;

    /// @notice Helper to get assertion creation code with mainnet perspectives
    function getMainnetAssertionCreationCode() internal pure returns (bytes memory) {
        address[] memory perspectives = new address[](2);
        perspectives[0] = MAINNET_GOVERNED_PERSPECTIVE;
        perspectives[1] = MAINNET_ESCROWED_COLLATERAL_PERSPECTIVE;
        return abi.encodePacked(type(VaultSharePriceAssertion).creationCode, abi.encode(perspectives));
    }

    /// @notice Helper to get assertion creation code with Linea perspectives
    function getLineaAssertionCreationCode() internal pure returns (bytes memory) {
        address[] memory perspectives = new address[](2);
        perspectives[0] = LINEA_GOVERNED_PERSPECTIVE;
        perspectives[1] = LINEA_ESCROWED_COLLATERAL_PERSPECTIVE;
        return abi.encodePacked(type(VaultSharePriceAssertion).creationCode, abi.encode(perspectives));
    }

    /// @notice Backtest batch operations against mainnet EVC
    function testBacktest_VaultSharePrice_BatchOperations() public {
        BacktestingTypes.BacktestingResults memory results = executeBacktest(
            BacktestingTypes.BacktestingConfig({
                targetContract: EVC_MAINNET,
                endBlock: MAINNET_END_BLOCK,
                blockRange: MAINNET_BLOCK_RANGE,
                assertionCreationCode: getMainnetAssertionCreationCode(),
                assertionSelector: VaultSharePriceAssertion.assertionBatchSharePriceInvariant.selector,
                rpcUrl: vm.envString("MAINNET_RPC_URL"),
                detailedBlocks: false,
                forkByTxHash: true
            })
        );

        // Verify no assertion failures in historical data
        assertEq(results.assertionFailures, 0, "Should not detect violations in healthy protocol");
    }

    /// @notice Backtest single call operations against mainnet EVC
    function testBacktest_VaultSharePrice_CallOperations() public {
        BacktestingTypes.BacktestingResults memory results = executeBacktest(
            BacktestingTypes.BacktestingConfig({
                targetContract: EVC_MAINNET,
                endBlock: MAINNET_END_BLOCK,
                blockRange: MAINNET_BLOCK_RANGE,
                assertionCreationCode: getMainnetAssertionCreationCode(),
                assertionSelector: VaultSharePriceAssertion.assertionCallSharePriceInvariant.selector,
                rpcUrl: vm.envString("MAINNET_RPC_URL"),
                detailedBlocks: false,
                forkByTxHash: true
            })
        );

        assertEq(results.assertionFailures, 0, "Should not detect violations in healthy protocol");
    }

    /// @notice Backtest control collateral operations against mainnet EVC
    function testBacktest_VaultSharePrice_ControlCollateralOperations() public {
        BacktestingTypes.BacktestingResults memory results = executeBacktest(
            BacktestingTypes.BacktestingConfig({
                targetContract: EVC_MAINNET,
                endBlock: MAINNET_END_BLOCK,
                blockRange: MAINNET_BLOCK_RANGE,
                assertionCreationCode: getMainnetAssertionCreationCode(),
                assertionSelector: VaultSharePriceAssertion.assertionControlCollateralSharePriceInvariant.selector,
                rpcUrl: vm.envString("MAINNET_RPC_URL"),
                detailedBlocks: false,
                forkByTxHash: true
            })
        );

        assertEq(results.assertionFailures, 0, "Should not detect violations in healthy protocol");
    }

    /// @notice Regression test for Linea tx 0x4ec425f3329c4e036c28df2d108341ad45a225edc42d22fb68dfc1ac52dc3738
    /// @dev This specific transaction triggered a false positive before the VIRTUAL_DEPOSIT formula was implemented.
    /// Keeping as a regression test with hardcoded values to ensure the fix remains effective.
    function testBacktest_VaultSharePrice_Linea_RegressionTest() public {
        // Use LINEA_RPC_URL if available, fallback to MAINNET_RPC_URL for local testing
        string memory rpcUrl;
        try vm.envString("LINEA_RPC_URL") returns (string memory url) {
            rpcUrl = url;
        } catch {
            rpcUrl = vm.envString("MAINNET_RPC_URL");
        }

        // Hardcoded values for the specific regression test transaction
        BacktestingTypes.BacktestingResults memory results = executeBacktest(
            BacktestingTypes.BacktestingConfig({
                targetContract: EVC_LINEA,
                endBlock: 27419134, // Block containing tx 0x4ec425f3...
                blockRange: 1,
                assertionCreationCode: getLineaAssertionCreationCode(),
                assertionSelector: VaultSharePriceAssertion.assertionBatchSharePriceInvariant.selector,
                rpcUrl: rpcUrl,
                detailedBlocks: false,
                forkByTxHash: true
            })
        );

        assertEq(results.assertionFailures, 0, "Regression test should pass");
    }

    /// @notice Backtest batch operations against Linea EVC
    function testBacktest_VaultSharePrice_Linea_BatchOperations() public {
        // Use LINEA_RPC_URL if available, fallback to MAINNET_RPC_URL for local testing
        string memory rpcUrl;
        try vm.envString("LINEA_RPC_URL") returns (string memory url) {
            rpcUrl = url;
        } catch {
            rpcUrl = vm.envString("MAINNET_RPC_URL");
        }

        BacktestingTypes.BacktestingResults memory results = executeBacktest(
            BacktestingTypes.BacktestingConfig({
                targetContract: EVC_LINEA,
                endBlock: LINEA_END_BLOCK,
                blockRange: LINEA_BLOCK_RANGE,
                assertionCreationCode: getLineaAssertionCreationCode(),
                assertionSelector: VaultSharePriceAssertion.assertionBatchSharePriceInvariant.selector,
                rpcUrl: rpcUrl,
                detailedBlocks: false,
                forkByTxHash: true
            })
        );

        assertEq(results.assertionFailures, 0, "Should not detect violations in healthy protocol");
    }

    /// @notice Backtest call operations against Linea EVC
    function testBacktest_VaultSharePrice_Linea_CallOperations() public {
        // Use LINEA_RPC_URL if available, fallback to MAINNET_RPC_URL for local testing
        string memory rpcUrl;
        try vm.envString("LINEA_RPC_URL") returns (string memory url) {
            rpcUrl = url;
        } catch {
            rpcUrl = vm.envString("MAINNET_RPC_URL");
        }

        BacktestingTypes.BacktestingResults memory results = executeBacktest(
            BacktestingTypes.BacktestingConfig({
                targetContract: EVC_LINEA,
                endBlock: LINEA_END_BLOCK,
                blockRange: LINEA_BLOCK_RANGE,
                assertionCreationCode: getLineaAssertionCreationCode(),
                assertionSelector: VaultSharePriceAssertion.assertionCallSharePriceInvariant.selector,
                rpcUrl: rpcUrl,
                detailedBlocks: false,
                forkByTxHash: true
            })
        );

        assertEq(results.assertionFailures, 0, "Should not detect violations in healthy protocol");
    }

    /// @notice Debug test for Linea tx 0xf2f84d5a619a1645f5530ae61613be751f277b6571e81e75c4a751c6cb1753ac
    /// @dev This specific transaction ran out of gas (3M) on staging
    function testBacktest_VaultSharePrice_Linea_DebugGasIssue() public {
        // Use LINEA_RPC_URL if available, fallback to MAINNET_RPC_URL for local testing
        string memory rpcUrl;
        try vm.envString("LINEA_RPC_URL") returns (string memory url) {
            rpcUrl = url;
        } catch {
            rpcUrl = vm.envString("MAINNET_RPC_URL");
        }

        // Block 28147579 contains the failing tx
        BacktestingTypes.BacktestingResults memory results = executeBacktest(
            BacktestingTypes.BacktestingConfig({
                targetContract: EVC_LINEA,
                endBlock: 28147579,
                blockRange: 1,
                assertionCreationCode: getLineaAssertionCreationCode(),
                assertionSelector: VaultSharePriceAssertion.assertionBatchSharePriceInvariant.selector,
                rpcUrl: rpcUrl,
                detailedBlocks: true,
                forkByTxHash: true
            })
        );

        assertEq(results.assertionFailures, 0, "Debug test should pass");
    }

    /// @notice Single transaction backtest for VaultSharePriceAssertion on Linea
    /// @dev Tests the batch share price invariant against a specific transaction
    function testBacktest_singleTx_lineaMainnet_VaultSharePriceAssertion() public {
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
            VaultSharePriceAssertion.assertionBatchSharePriceInvariant.selector,
            rpcUrl
        );

        assertEq(results.assertionFailures, 0, "Single tx backtest should pass");
    }
}
