// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../interfaces/ICreditVault.sol";
import "../interfaces/ICreditVaultProtocol.sol";

abstract contract CreditVaultBase is ICreditVault {
    error Reentrancy();
    error MustBeNonReentrant();
    error NotAuthorized();
    error ControllerDisabled();

    ICVP public immutable cvp;
    uint private reentrancyGuard;
    bytes private transientBytes;
    
    bytes32 constant private EMPTY_BYTES = keccak256(bytes(""));
    uint constant private REENTRANCY_GUARD_INIT = 1;
    uint constant private REENTRANCY_GUARD_BUSY = 2;
    uint constant private REENTRANCY_GUARD_CHECKS_IN_PROGRESS = 3;
    
    constructor(ICVP _cvp) {
        cvp = _cvp;
        reentrancyGuard = REENTRANCY_GUARD_INIT;
    }

    modifier nonReentrant() {
        if (reentrancyGuard != REENTRANCY_GUARD_INIT) revert Reentrancy();

        reentrancyGuard = REENTRANCY_GUARD_BUSY;
        _;
        reentrancyGuard = REENTRANCY_GUARD_INIT;

        delete transientBytes;
    }

    modifier checksInProgress() {
        if (reentrancyGuard != REENTRANCY_GUARD_BUSY) revert MustBeNonReentrant();

        reentrancyGuard = REENTRANCY_GUARD_CHECKS_IN_PROGRESS;
        _;
        reentrancyGuard = REENTRANCY_GUARD_BUSY;
    }

    modifier nonReentrantRO() {
        if (reentrancyGuard != REENTRANCY_GUARD_INIT) revert Reentrancy();
        _;
    }

    modifier CVPOnly() {
        if (msg.sender != address(cvp)) revert NotAuthorized();
        _;
    }

    function CVPAuthenticate(address msgSender, bool controllerEnabledCheck) internal view 
    returns (address authMsgSender) {
        if (msgSender == address(cvp)) {
            bool controllerEnabled;
            (authMsgSender, controllerEnabled, ) = cvp.getExecutionContext(address(this));
            if (controllerEnabledCheck && !controllerEnabled) revert ControllerDisabled();
        } else {
            authMsgSender = msgSender;
            if (controllerEnabledCheck && !cvp.isControllerEnabled(authMsgSender, address(this))) revert ControllerDisabled();
        }
    }

    function vaultStatusSnapshot() internal {
        if (reentrancyGuard != REENTRANCY_GUARD_BUSY) revert MustBeNonReentrant();
        if (keccak256(transientBytes) == EMPTY_BYTES) transientBytes = doVaultStatusSnapshot();
    }

    function requireVaultStatusCheck() internal checksInProgress {
        cvp.requireVaultStatusCheck();
    }

    function requireAccountStatusCheck(address account) internal checksInProgress {
        cvp.requireAccountStatusCheck(account);
    }

    function requireAccountsStatusCheck(address[] memory accounts) internal checksInProgress {
        cvp.requireAccountsStatusCheck(accounts);
    }

    function checkAccountStatus(address account, address[] calldata collaterals) external view 
    returns (bool isValid, bytes memory data) {
        uint reentrancyGuardCache = reentrancyGuard;

        if (
            reentrancyGuardCache != REENTRANCY_GUARD_INIT && 
            reentrancyGuardCache != REENTRANCY_GUARD_CHECKS_IN_PROGRESS
        ) revert Reentrancy();

        (isValid, data) = doCheckAccountStatus(account, collaterals);
    }

    function checkVaultStatus() external CVPOnly returns (bool isValid, bytes memory data) {
        uint reentrancyGuardCache = reentrancyGuard;

        if (
            reentrancyGuardCache != REENTRANCY_GUARD_INIT && 
            reentrancyGuardCache != REENTRANCY_GUARD_CHECKS_IN_PROGRESS
        ) revert Reentrancy();

        if (keccak256(transientBytes) == EMPTY_BYTES) return (true, data);

        (isValid, data) = doCheckVaultStatus(transientBytes);
    }

    function doVaultStatusSnapshot() internal view virtual returns (bytes memory snapshot);

    function doCheckVaultStatus(bytes memory snapshot) internal virtual returns (bool isValid, bytes memory data);

    function doCheckAccountStatus(address, address[] calldata) internal view virtual returns (bool isValid, bytes memory data);

    function disableController(address account) external virtual;
}
