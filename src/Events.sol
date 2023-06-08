// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./Storage.sol";

abstract contract Events {
    event Genesis();


    event ProxyCreated(address indexed proxy, uint moduleId);
    event MarketRegistered(address indexed market);
    event MarketActivated(address indexed market, address indexed marketCreator, uint8 hookBitmask, uint8 pauseBitmask);

    event AddCollateral(address indexed market, address indexed account);
    event RemoveCollateral(address indexed market, address indexed account);

    event InstallerSetUpgradeAdmin(address indexed newUpgradeAdmin);
    event InstallerSetGovernorAdmin(address indexed newGovernorAdmin);
    event InstallerInstallModule(uint indexed moduleId, address indexed moduleImpl, bytes32 moduleGitCommit);

    event GovResetReentrancy();
    event GovSetEulerFactory(address indexed eulerFactory);
    event GovSetMarketGovernor(address indexed market, address governor);
    event GovSetHookBitmask(address indexed market, uint24 bitmask);
    event GovSetPauseBitmask(address indexed market, uint8 bitmask);
    event GovSetAccountOperator(address indexed account, address operator);
}
