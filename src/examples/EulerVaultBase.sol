// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../interfaces/IEulerVault.sol";
import "../interfaces/IEulerConductor.sol";

abstract contract EulerVaultBase is IEulerVault {
    struct ConductorContext {
        bool conductorCalling;
        bool checksDeferred;
        bool contextExtended;
        bool controllerEnabled;
        address onBehalfOfAccount;
    }

    error Reentrancy();
    error ReentrancyOrderViolation();
    error NotAuthorized();
    error ControllerDisabled();

    uint private reentrancyGuard;
    bytes internal transientBytes;
    address public immutable eulerConductor;

    uint constant private REENTRANCY_GUARD_INIT = 1;
    uint constant private REENTRANCY_GUARD_BUSY = 2;
    uint constant private REENTRANCY_GUARD_ACCOUNT_STATUS_CHECK = 3;
    
    constructor(address _eulerConductor) {
        eulerConductor = _eulerConductor;
        reentrancyGuard = REENTRANCY_GUARD_INIT;
    }

    modifier nonReentrant() {
        if (reentrancyGuard != REENTRANCY_GUARD_INIT) revert Reentrancy();

        reentrancyGuard = REENTRANCY_GUARD_BUSY;

        _;

        reentrancyGuard = REENTRANCY_GUARD_INIT;
    }

    modifier nonReentrantRO() {
        if (reentrancyGuard != REENTRANCY_GUARD_INIT) revert Reentrancy();
        _;
    }

    function conductorContext() internal view returns (ConductorContext memory context) {
        context.conductorCalling = msg.sender == eulerConductor;

        if (context.conductorCalling) {
            (
                context.checksDeferred, 
                context.onBehalfOfAccount
            ) = IEulerConductor(eulerConductor).getExecutionContext();
        }
    }

    function conductorAuthenticate(address account, bool controllerEnabledCheck) internal view
    returns (ConductorContext memory context) {
        context.conductorCalling = msg.sender == eulerConductor;

        if (context.conductorCalling) {
            context.contextExtended = controllerEnabledCheck;

            if (controllerEnabledCheck) {
                (
                    context.checksDeferred, 
                    context.onBehalfOfAccount, 
                    context.controllerEnabled
                ) = IEulerConductor(eulerConductor).getExecutionContextExtended(account, address(this));
            } else {
                (
                    context.checksDeferred, 
                    context.onBehalfOfAccount
                ) = IEulerConductor(eulerConductor).getExecutionContext();
            }

            if (context.onBehalfOfAccount != account) revert NotAuthorized();
            if (controllerEnabledCheck && !context.controllerEnabled) revert ControllerDisabled();
        } else if (controllerEnabledCheck) {
            if (!IEulerConductor(eulerConductor).isControllerEnabled(account, address(this))) revert ControllerDisabled();
        }
    }

    function accountStatusCheck(address account, ConductorContext memory context) internal {
        if (reentrancyGuard != REENTRANCY_GUARD_BUSY) revert ReentrancyOrderViolation();

        if (!context.checksDeferred || context.onBehalfOfAccount != account) {
            reentrancyGuard = REENTRANCY_GUARD_ACCOUNT_STATUS_CHECK;

            IEulerConductor(eulerConductor).requireAccountStatusCheck(account);

            reentrancyGuard = REENTRANCY_GUARD_BUSY;
        }
    }

    function preVaultStatusCheck(ConductorContext memory context) internal {
        if (!context.conductorCalling) transientBytes = vaultStatusHook(true, abi.encode(0));
    }

    function postVaultStatusCheck(ConductorContext memory context) internal {
        if (!context.conductorCalling) {
            vaultStatusHook(false, transientBytes);
            delete transientBytes;
        }
    }

    function checkAccountStatus(address account, address[] calldata collaterals) external view 
    returns (bool isValid) {
        uint reentrancyGuardCache = reentrancyGuard;

        if (
            reentrancyGuardCache != REENTRANCY_GUARD_INIT && 
            reentrancyGuardCache != REENTRANCY_GUARD_ACCOUNT_STATUS_CHECK
        ) revert Reentrancy();

        isValid = checkAccountStatusInternal(account, collaterals);
    }

    function checkAccountStatusInternal(address, address[] calldata) internal view virtual returns (bool isValid);

    function vaultStatusHook(bool initialCall, bytes memory data) public view virtual returns (bytes memory result);

    function disableController(address account) external virtual;
}
