// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IEVC} from "../interfaces/IEthereumVaultConnector.sol";
import {ExecutionContext, EC} from "../ExecutionContext.sol";

/// @title EVCUtil
/// @custom:security-contact security@euler.xyz
/// @author Euler Labs (https://www.eulerlabs.com/)
/// @notice This contract is an abstract base contract for interacting with the Ethereum Vault Connector (EVC).
/// It provides utility functions for authenticating the callers in the context of the EVC, a pattern for enforcing the
/// contracts to be called through the EVC.
abstract contract EVCUtil {
    using ExecutionContext for EC;

    uint160 internal constant ACCOUNT_ID_OFFSET = 8;
    IEVC internal immutable evc;

    error EVC_InvalidAddress();
    error NotAuthorized();
    error ControllerDisabled();

    constructor(address _evc) {
        if (_evc == address(0)) revert EVC_InvalidAddress();

        evc = IEVC(_evc);
    }

    /// @notice Returns the address of the Ethereum Vault Connector (EVC) used by this contract.
    /// @return The address of the EVC contract.
    function EVC() external view virtual returns (address) {
        return address(evc);
    }

    /// @notice Ensures that the msg.sender is the EVC by using the EVC callback functionality if necessary.
    /// @dev Optional to use for functions requiring account and vault status checks to enforce predictable behavior.
    /// @dev If this modifier used in conjuction with any other modifier, it must appear as the first (outermost)
    /// modifier of the function.
    modifier callThroughEVC() virtual {
        _callThroughEVC();
        _;
    }

    /// @notice Ensures that the caller is the EVC in the appropriate context.
    /// @dev Should be used for checkAccountStatus and checkVaultStatus functions.
    modifier onlyEVCWithChecksInProgress() virtual {
        _onlyEVCWithChecksInProgress();
        _;
    }

    /// @notice Ensures a standard authentication path on the EVC allowing the account owner or any of its EVC accounts.
    /// @dev This modifier checks if the caller is the EVC and if so, verifies the execution context.
    /// It reverts if the operator is authenticated, control collateral is in progress, or checks are in progress.
    /// @dev This modifier must not be used on functions utilized by liquidation flows, i.e. transfer or withdraw.
    /// @dev This modifier must not be used on checkAccountStatus and checkVaultStatus functions.
    /// @dev This modifier can be used on access controlled functions to prevent non-standard authentication paths on
    /// the EVC.
    modifier onlyEVCAccount() virtual {
        _authenticateCallerWithStandardContextState(false);
        _;
    }

    /// @notice Ensures a standard authentication path on the EVC.
    /// @dev This modifier checks if the caller is the EVC and if so, verifies the execution context.
    /// It reverts if the operator is authenticated, control collateral is in progress, or checks are in progress.
    /// It reverts if the authenticated account owner is known and it is not the account owner.
    /// @dev It assumes that if the caller is not the EVC, the caller is the account owner.
    /// @dev This modifier must not be used on functions utilized by liquidation flows, i.e. transfer or withdraw.
    /// @dev This modifier must not be used on checkAccountStatus and checkVaultStatus functions.
    /// @dev This modifier can be used on access controlled functions to prevent non-standard authentication paths on
    /// the EVC.
    modifier onlyEVCAccountOwner() virtual {
        _authenticateCallerWithStandardContextState(true);
        _;
    }

    /// @notice Checks whether the specified account and the other account have the same owner.
    /// @dev The function is used to check whether one account is authorized to perform operations on behalf of the
    /// other. Accounts are considered to have a common owner if they share the first 19 bytes of their address.
    /// @param account The address of the account that is being checked.
    /// @param otherAccount The address of the other account that is being checked.
    /// @return A boolean flag that indicates whether the accounts have the same owner.
    function _haveCommonOwner(address account, address otherAccount) internal pure returns (bool) {
        bool result;
        assembly {
            result := lt(xor(account, otherAccount), 0x100)
        }
        return result;
    }

    /// @notice Returns the address prefix of the specified account.
    /// @dev The address prefix is the first 19 bytes of the account address.
    /// @param account The address of the account whose address prefix is being retrieved.
    /// @return A bytes19 value that represents the address prefix of the account.
    function _getAddressPrefix(address account) internal pure returns (bytes19) {
        return bytes19(uint152(uint160(account) >> ACCOUNT_ID_OFFSET));
    }

    /// @notice Retrieves the message sender in the context of the EVC.
    /// @dev This function returns the account on behalf of which the current operation is being performed, which is
    /// either msg.sender or the account authenticated by the EVC.
    /// @return The address of the message sender.
    function _msgSender() internal view virtual returns (address) {
        address sender = msg.sender;

        if (sender == address(evc)) {
            (sender,) = evc.getCurrentOnBehalfOfAccount(address(0));
        }

        return sender;
    }

    /// @notice Retrieves the message sender in the context of the EVC for a borrow operation.
    /// @dev This function returns the account on behalf of which the current operation is being performed, which is
    /// either msg.sender or the account authenticated by the EVC. This function reverts if this contract is not enabled
    /// as a controller for the account on behalf of which the operation is being executed.
    /// @return The address of the message sender.
    function _msgSenderForBorrow() internal view virtual returns (address) {
        address sender = msg.sender;
        bool controllerEnabled;

        if (sender == address(evc)) {
            (sender, controllerEnabled) = evc.getCurrentOnBehalfOfAccount(address(this));
        } else {
            controllerEnabled = evc.isControllerEnabled(sender, address(this));
        }

        if (!controllerEnabled) {
            revert ControllerDisabled();
        }

        return sender;
    }

    /// @notice Retrieves the message sender, ensuring it's any EVC account meaning that the execution context is in a
    /// standard state (not operator authenticated, not control collateral in progress, not checks in progress).
    /// @dev This function must not be used on functions utilized by liquidation flows, i.e. transfer or withdraw.
    /// @dev This function must not be used on checkAccountStatus and checkVaultStatus functions.
    /// @dev This function can be used on access controlled functions to prevent non-standard authentication paths on
    /// the EVC.
    /// @return The address of the message sender.
    function _msgSenderOnlyEVCAccount() internal view returns (address) {
        return _authenticateCallerWithStandardContextState(false);
    }

    /// @notice Retrieves the message sender, ensuring it's the EVC account owner and that the execution context is in a
    /// standard state (not operator authenticated, not control collateral in progress, not checks in progress).
    /// @dev It assumes that if the caller is not the EVC, the caller is the account owner.
    /// @dev This function must not be used on functions utilized by liquidation flows, i.e. transfer or withdraw.
    /// @dev This function must not be used on checkAccountStatus and checkVaultStatus functions.
    /// @dev This function can be used on access controlled functions to prevent non-standard authentication paths on
    /// the EVC.
    /// @return The address of the message sender.
    function _msgSenderOnlyEVCAccountOwner() internal view returns (address) {
        return _authenticateCallerWithStandardContextState(true);
    }

    /// @notice Calls the current external function through the EVC.
    /// @dev This function is used to route the current call through the EVC if it's not already coming from the EVC. It
    /// makes the EVC set the execution context and call back this contract with unchanged calldata. msg.sender is used
    /// as the onBehalfOfAccount.
    /// @dev This function shall only be used by the callThroughEVC modifier.
    function _callThroughEVC() internal {
        address _evc = address(evc);
        if (msg.sender == _evc) return;

        assembly {
            mstore(0, 0x1f8b521500000000000000000000000000000000000000000000000000000000) // EVC.call selector
            mstore(4, address()) // EVC.call 1st argument - address(this)
            mstore(36, caller()) // EVC.call 2nd argument - msg.sender
            mstore(68, callvalue()) // EVC.call 3rd argument - msg.value
            mstore(100, 128) // EVC.call 4th argument - msg.data, offset to the start of encoding - 128 bytes
            mstore(132, calldatasize()) // msg.data length
            calldatacopy(164, 0, calldatasize()) // original calldata

            // abi encoded bytes array should be zero padded so its length is a multiple of 32
            // store zero word after msg.data bytes and round up calldatasize to nearest multiple of 32
            mstore(add(164, calldatasize()), 0)
            let result := call(gas(), _evc, callvalue(), 0, add(164, and(add(calldatasize(), 31), not(31))), 0, 0)

            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(64, sub(returndatasize(), 64)) } // strip bytes encoding from call return
        }
    }

    /// @notice Ensures that the function is called only by the EVC during the checks phase
    /// @dev Reverts if the caller is not the EVC or if checks are not in progress.
    function _onlyEVCWithChecksInProgress() internal view {
        if (msg.sender != address(evc) || !evc.areChecksInProgress()) {
            revert NotAuthorized();
        }
    }

    /// @notice Ensures that the function is called only by the EVC account owner or any of its EVC accounts
    /// @dev This function checks if the caller is the EVC and if so, verifies that the execution context is not in a
    /// special state (operator authenticated, collateral control in progress, or checks in progress). If
    /// onlyAccountOwner is true and the owner was already registered on the EVC, it verifies that the onBehalfOfAccount
    /// is the owner. If onlyAccountOwner is false, it allows any EVC account of the owner to call the function.
    /// @param onlyAccountOwner If true, only allows the account owner; if false, allows any EVC account of the owner
    /// @return The address of the message sender.
    function _authenticateCallerWithStandardContextState(bool onlyAccountOwner) internal view returns (address) {
        if (msg.sender == address(evc)) {
            EC ec = EC.wrap(evc.getRawExecutionContext());

            if (ec.isOperatorAuthenticated() || ec.isControlCollateralInProgress() || ec.areChecksInProgress()) {
                revert NotAuthorized();
            }

            address onBehalfOfAccount = ec.getOnBehalfOfAccount();

            if (onlyAccountOwner) {
                address owner = evc.getAccountOwner(onBehalfOfAccount);

                if (owner != address(0) && owner != onBehalfOfAccount) {
                    revert NotAuthorized();
                }
            }

            return onBehalfOfAccount;
        }

        return msg.sender;
    }
}
