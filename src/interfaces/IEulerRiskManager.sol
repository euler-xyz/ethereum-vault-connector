// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;


interface IEulerRiskManager {
    struct LiquidityStatus {
        uint collateralValue;
        uint liabilityValue;
    }

    struct MarketLiquidity {
        address market;
        LiquidityStatus status;
    }

    struct LiquidationOpportunity {
        uint repay;
        uint yield;
    }

    function computeLiquidity(address account, address[] memory collaterals) external view returns (LiquidityStatus memory liquidity);
    function computeLiquidities(address account, address[] memory collaterals) external view returns (MarketLiquidity[] memory liquidities);
    function computeCollateralValue(address account) external view returns (uint collateralValue);
    function checkLiquidity(address account, address[] memory collaterals) external view returns (bool isLiquid);
    function computeLiquidation(address liquidator, address violator, address[] memory collaterals, uint8 seizeIndex) external view returns (LiquidationOpportunity memory liqOpp, LiquidityStatus memory liqStat);
    function getPrice(address market) external view returns (bytes memory price);
}
