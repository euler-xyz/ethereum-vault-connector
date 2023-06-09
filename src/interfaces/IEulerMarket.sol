// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

interface IEulerMarket {
    function disableLiabilityMarket(address account) external;
    function hook(uint hookNumber, bytes memory data) external returns (bytes memory returnData);
}
