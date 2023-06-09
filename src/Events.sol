// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./Storage.sol";

abstract contract Events {
    event Genesis();
    event MarketActivated(address indexed market, address indexed marketCreator);

    event GovSetGovernorAdmin(address indexed admin);
    event GovSetEulerMarketRegistry(address indexed registry);
    event GovSetAccountOperator(address indexed account, address operator);
}
