// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../BaseModule.sol";


contract Installer is BaseModule {
    constructor(bytes32 moduleGitCommit_) BaseModule(MODULEID__INSTALLER, moduleGitCommit_) {}

    modifier adminOnly {
        address msgSender = unpackTrailingParamMsgSender();
        require(msgSender == upgradeAdmin, "e/installer/unauthorized");
        _;
    }

    function getUpgradeAdmin() external view returns (address) {
        return upgradeAdmin;
    }

    function setUpgradeAdmin(address newUpgradeAdmin) external nonReentrant adminOnly {
        require(newUpgradeAdmin != address(0), "e/installer/bad-admin-addr");
        upgradeAdmin = newUpgradeAdmin;
        emit InstallerSetUpgradeAdmin(newUpgradeAdmin);
    }

    function getGovernorAdmin() external view returns (address) {
        return governorAdmin;
    }

    function setGovernorAdmin(address newGovernorAdmin) external nonReentrant adminOnly {
        require(newGovernorAdmin != address(0), "e/installer/bad-gov-addr");
        governorAdmin = newGovernorAdmin;
        emit InstallerSetGovernorAdmin(newGovernorAdmin);
    }

    function installModules(address[] memory moduleAddrs) external nonReentrant adminOnly {
        for (uint i = 0; i < moduleAddrs.length; ++i) {
            address moduleAddr = moduleAddrs[i];
            uint newModuleId = BaseModule(moduleAddr).moduleId();
            bytes32 newModuleGitCommit = BaseModule(moduleAddr).moduleGitCommit();

            moduleLookup[newModuleId] = moduleAddr;
            _createProxy(newModuleId, moduleAddr);

            emit InstallerInstallModule(newModuleId, moduleAddr, newModuleGitCommit);
        }
    }
}
