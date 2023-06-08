// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;
//import "hardhat/console.sol"; // DEV_MODE

import "./Storage.sol";
import "./Events.sol";
import "./Proxy.sol";

abstract contract Base is Storage, Events {
    // Account auth

    function getSubAccount(address primary, uint subAccountId) internal pure returns (address) {
        require(subAccountId < 256, "e/sub-account-id-too-big");
        return address(uint160(primary) ^ uint160(subAccountId));
    }

    function isSubAccountOf(address primary, address subAccount) internal pure returns (bool) {
        return (uint160(primary) | 0xFF) == (uint160(subAccount) | 0xFF);
    }


    // Modules

    function _createProxy(uint proxyModuleId, address implementation) internal returns (address) {
        require(proxyModuleId != 0, "e/create-proxy/invalid-module");

        // If we've already created a proxy for a single-proxy module, just return it:

        if (proxyLookup[proxyModuleId] != address(0)) return proxyLookup[proxyModuleId];

        // Otherwise create a proxy:

        address proxyAddr = address(new Proxy());

        proxyLookup[proxyModuleId] = proxyAddr;

        trustedSenders[proxyAddr] = TrustedSenderInfo({ moduleId: uint32(proxyModuleId), moduleImpl: implementation });

        emit ProxyCreated(proxyAddr, proxyModuleId);

        return proxyAddr;
    }

    // Modifiers

    modifier nonReentrant() {
        checkReentrancyUnlockedAndSetLocked();

        _;
        
        setReentrancyUnlocked();
    }

    modifier reentrantOK() { // documentation only
        _;
    }

    // Used to flag functions which do not modify storage, but do perform a delegate call
    // to a view function, which prohibits a standard view modifier. The flag is used to
    // patch state mutability in compiled ABIs and interfaces.
    modifier staticDelegate() {
        _;
    }

    // Auxiliary functions

    function checkReentrancyUnlockedAndSetLocked() internal {
        require((REENTRANCYLOCK__LOCK & reentrancyLock) == 0, "e/reentrancy-locked");

        reentrancyLock |= REENTRANCYLOCK__LOCK;
    }

    function setReentrancyUnlocked() internal virtual {
        reentrancyLock &= ~REENTRANCYLOCK__LOCK;
    }

    // Error handling

    function revertBytes(bytes memory errMsg) internal pure {
        if (errMsg.length > 0) {
            assembly {
                revert(add(32, errMsg), mload(errMsg))
            }
        }

        revert("e/empty-error");
    }
}
