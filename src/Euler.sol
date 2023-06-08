// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "./Base.sol";


/// @notice Main storage contract for the Euler system
contract Euler is Base {
    constructor(address admin, address installerModule) {
        emit Genesis();

        reentrancyLock = REENTRANCYLOCK__INIT_STATE;
        upgradeAdmin = admin;
        governorAdmin = admin;

        moduleLookup[MODULEID__INSTALLER] = installerModule;
        _createProxy(MODULEID__INSTALLER, installerModule);
    }

    string public constant name = "Euler Protocol";

    /// @notice Lookup the current implementation contract for a module
    /// @param moduleId Fixed constant that refers to a module type (ie MODULEID__ETOKEN)
    /// @return An internal address specifies the module's implementation code
    function moduleIdToImplementation(uint moduleId) external view returns (address) {
        return moduleLookup[moduleId];
    }

    /// @notice Lookup a proxy that can be used to interact with a module (only valid for single-proxy modules)
    /// @param moduleId Fixed constant that refers to a module type (ie MODULEID__MARKETS)
    /// @return An address that should be cast to the appropriate module interface, ie IEulerMarkets(moduleIdToProxy(2))
    function moduleIdToProxy(uint moduleId) external view returns (address) {
        return proxyLookup[moduleId];
    }

    function dispatch() external reentrantOK {
        uint32 moduleId = trustedSenders[msg.sender].moduleId;
        address moduleImpl = trustedSenders[msg.sender].moduleImpl;

        require(moduleId != 0 && moduleImpl != address(0), "e/sender-not-trusted");

        uint msgDataLength = msg.data.length;
        require(msgDataLength >= (4 + 4 + 20), "e/input-too-short");

        assembly {
            let payloadSize := sub(calldatasize(), 4)
            calldatacopy(0, 4, payloadSize)
            mstore(payloadSize, shl(96, caller()))

            let result := delegatecall(gas(), moduleImpl, 0, add(payloadSize, 20), 0, 0)

            returndatacopy(0, 0, returndatasize())

            switch result
                case 0 { revert(0, returndatasize()) }
                default { return(0, returndatasize()) }
        }
    }
}
