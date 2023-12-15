# Ethereum Vault Connector and Vault Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## Definitions

- Ethereum Vault Connector (EVC): A smart contract that mediates between Vaults in order to enable their lending and borrowing functionality.
- Vault: A smart contract that accepts deposits of a single asset and issues shares in return, it MAY support borrowing functionality. It SHOULD implement the logic and interface necessary for interaction with other Vaults via the EVC. It MAY be, ERC-4626 compliant.
- Account: Every Ethereum address has 256 accounts in the EVC (one private key to rule them all). Each account has an account ID from 0-255. In order to compute the account addresses, the Account ID is treated as a uint and XORed (exclusive ORed) with the Ethereum address. Effectively, a group of 256 Accounts belonging to the same owner share the first 19 bytes of their address and differ only in the last byte.
- Account Owner: An EOA or a smart contract Ethereum address, one of the 256 Accounts with Account ID 0, that has ownership over the whole group of Accounts.
- Address Prefix: The first 19 bytes of the Ethereum address. Account Owner has a common Address Prefix with any of the Accounts that belong to them.
- Account Operator: An EOA or smart contract Ethereum address that has been granted a permission to operate on behalf of the Account. The permission can only be granted by the Account Owner.
- Collateral Vault: A Vault which deposits are recognized as collateral for borrowing in other Vaults. An Account can enable multiple collaterals. Enabled collateral can be seized by the Controller Vault in case of liquidation.
- Controller Vault: A Vault which may be enabled by a user in order to be able to borrow from it. Enabling Controller submits the specified Account to the rules encoded in the Controller Vault's code. All the funds in all the enabled Collateral Vaults are indirectly under control of the enabled Controller Vault hence the Accounts MUST only enable trusted, audited Controllers. If the Controller is malicious or incorrectly coded, it may result in the loss of the user's funds or even render the account unusable. Whenever a user wants to perform an action such as removing collateral, the Controller Vault is consulted in order to determine whether the action is allowed, or whether it should be blocked since it would make the Account insolvent. An Account can have only one Controller Vault enabled at a time unless it's a transient state during checks deferral.
- Nonce Namespace: A value used in conjunction with Nonce to prevent replaying Permit messages and for sequencing. Each Nonce Namespace provides a uint256 Nonce that has to be used sequentially. There's no requirement to use all the Nonces for a given Nonce Namespace before moving to the next one which allows to use Permit messages in a non-sequential manner.
- Nonce: A value used to prevent replaying Permit messages, and for sequencing. It is associated with a specific Nonce Namespace and an Address Prefix. The Nonce must be used sequentially within its Nonce Namespace. To invalidate signed Permit messages, set the Nonce for a given Nonce Namespace accordingly. To invalidate all the Permit messages for a given Nonce Namespace, set the Nonce to type(uint).max.
- Permit: A functionality based on the EIP-712 typed data message allowing arbitrary signed calldata execution on the EVC on behalf of the signer (Account Owner or Account Operator) of the message. It is useful for implementing "gasless" transactions.
- Call: A functionality allowing to execute arbitrary calldata on an arbitrary contract with Account and Vault Status Checks deferred. In case the target contract is msg.sender, the caller MAY specify any Account address to be set in the Execution Context. In case the target contract is not msg.sender, only the Account Owner or Account Operator are allowed to to execute arbitrary calldata on behalf of the specified Account.
- Impersonate: A functionality allowing an enabled Controller Vault to execute an arbitrary calldata on any of the enabled Collateral Vaults on behalf of the specified Account while Account and Vault Status Checks are deferred. The Controller Vault must be the only enabled Controller Vault for the Account in order to be able to impersonate the Account. Impersonation is useful for liquidation flows.
- Batch: A list of operations that are executed atomically one by one with Account and Vault Status Checks deferred.
- Simulation: An entry point into the EVC that allows for simulating the execution of a batch without modifying the state. It is useful for inspecting the outcome of a batch before executing it.
- Account Status Check: A functionality implemented by Vaults to enforce Account solvency. Vaults MUST expose a special function that will receive an Account address and this Account's list of enabled Collateral Vaults in order to determine the Account's liquidity status. Account status is checked immediately or is deferred until the end of the top-level Checks-deferrable Call. Account Status Check deferral allows for a transient violation of the Account solvency.
- Vault Status Check: A functionality implemented by Vaults to enforce Vault constraints (i.e. supply/borrow caps). Vaults MAY expose a special function that implements necessary checks in order to determine acceptable state of the Vault. Vault status is checked immediately or is deferred until the end of the top-level Checks-deferrable Call. Vault Status Check deferral allows for a transient violation of the Vault constraints.
- Checks-deferrable Call: Any of the function calls that defers the Account and Vault Status Checks, namely: Call, Impersonate, or Batch call. Checks-deferrable Calls can be nested.
- Checks Deferral: A functionality allowing to defer Account and Vault Status Checks until the end of the top-level Checks-deferrable Call. This allows for a transient violation of the Account solvency or Vault constraints.
- Execution Context: A data structure maintained by the EVC which holds information about current execution state. It tracks the Checks-deferrable Calls depth, currently authenticated Account address on behalf of which current operation is being performed, a flag indicating whether the Account/Vault Status Checks are in progress, a flag indicating whether the Impersonate is in progress, a flag indicating whether an Account Operator is currently operating on behalf of the Account and a flag indicating whether the Simulation is in progress.


## Ethereum Vault Connector Specification

1. An Owner of the group of 256 accounts MUST be recorded only once upon the first interaction of any of its Accounts with the EVC.
1. Only an Account Owner MUST be allowed to authorize an Account Operator to operate on behalf of the Account.
1. An Account MAY have multiple Account Operators.
1. Account Operator address MUST NOT belong to the Account Owner of the Account for which the Operator being is authorized.
1. Account Operator MUST be allowed to deauthorize itself for the Account if it is authorized to operate on behalf of it.
1. Only an Account Owner MUST be allowed to modify the Nonce for its Address Prefix and Nonce Namespace.
1. New Nonce MUST NOT be lower than the currently stored.
1. Each Account MUST have at most 20 Collateral Vaults enabled at a time.
1. Each Account MUST have at most one Controller Vault enabled at a time unless it's a transient state during a Checks-deferrable Call.
1. Only an Account Owner or the Account Operator MUST be allowed to enable and disable Collateral Vaults for the Account.
1. Only an Account Owner or the Account Operator MUST be allowed to reorder enabled Collateral Vaults for the Account.
1. Only an Account Owner or the Account Operator MUST be allowed to enable Controller Vaults for the Account.
1. Only an enabled Controller Vault for the Account MUST be allowed to disable itself for that Account.
1. The Controller Vault MUST NOT be allowed to use Permit message in order to disable itself for an Account.
1. EVC MUST support signed Permit messages that allow anyone to execute arbitrary calldata on the EVC on behalf of the Account Owner or Account Operator who signed the message.
1. Signed Permit message MUST conform to the EIP-712 standard rules.
1. The type of the EIP-712 data structure MUST be encoded as follows: `Permit(address signer,uint256 nonceNamespace,uint256 nonce,uint256 deadline,uint256 value,bytes data)`.
1. For the signature to be considered valid, all of the below MUST be true:
- the `signer` address corresponds to the valid signer address obtained using standard `ecrecover` precompile or using ERC-1271 defined rules for standard signature verification methods for contracts
- `nonce` is equal to the current on-chain Nonce value for `signer`-corresponding Address Prefix and `nonceNamespace`
- `deadline` value is not greater than `block.timestamp` at the block of signature verification
- `value` does not exceed ETH balance of the EVC contract at the time of signature verification, or is equal to `type(uint256).max`
- `data` field is not empty
1. Upon successful verification of the signature, EVC MUST increase the Nonce value corresponding to the Nonce Namespace and signer.
1. The authorization rules of the Permit message calldata execution MUST be as if it were the Account Owner or Account Operator executing that calldata themselves.
1. EVC MUST support the following Checks-deferrable Call functions: Call, Impersonate and Batch that are re-entrant and allow to execute calldata on an external target addresses.
1. Each Checks-deferrable Call function MUST specify an Account. The functions MUST determine whether or not `msg.sender` is authorized to perform operations on that Account. If the target contract is not `msg.sender`, only the Owner or an Operator of the specified Account MUST be allowed to perform Call and individual Batch operations on behalf of the Account. Only the enabled Controller of the specified Account MUST be allowed to perform Impersonate operation on behalf of the Account.
1. EVC MUST maintain the Execution Context and make it publicly observable.
1. Execution Context MUST keep track of Checks-deferrable Call nesting depth counter starting at 0. The depth counter MUST increase by 1 every time Checks-deferrable Call is entered and MUST decrease by 1 when Checks-deferrable Call is exited.
1. Execution Context MUST keep track of the Account on behalf of which current low-level calldata call is being performed.
1. Execution Context MUST keep track of whether the Account and Vault Status Checks are in progress.
1. Execution Context MUST keep track of whether the Impersonate is in progress.
1. Execution Context MUST keep track of whether an Account Operator was authenticated to perform the current low-level calldata call on behalf of the Account.
1. Execution Context MUST keep track of whether the Simulation is in progress.
1. EVC MUST allow to require Account and Vault Status Checks which will be performed immediately or deferred, depending on the Execution Context.
1. EVC MUST allow to defer required Account and Vault Status Checks performance until the Checks-deferrable Call nesting depth counter is decreased back to the default value of 0. That SHOULD allow for a transient violation of the Account solvency or Vault constraints.
1. If the execution is not within a Checks-deferrable Call, meaning the Checks-deferrable Call nesting depth counter is 0, required Account and Vault Status Checks MUST be performed immediately.
1. For the Account Status Check to be performed, there MUST be only one Controller enabled for an Account at the time of the Check.
1. If there is no Controller enabled for an Account at the time of the Check, the Account Status MUST always be considered valid. It includes disabling the only enabled Controller before the Checks.
1. If there is more than one Controller enabled for an Account at the time of the Check, the Account Status MUST always be considered invalid.
1. Both Account- and Vault-Status-Checks-related storage sets MUST return to their default state when the Checks-deferrable Call nesting depth counter is 0 and the checks were performed.
1. EVC MUST allow for Checks-deferrable Calls to be nested up to 10 levels deep.
1. EVC MUST allow for Account Status Checks to be deferred for at most 20 Accounts at a time.
1. EVC MUST allow for Vault Status Checks to be deferred for at most 20 Vaults at a time.
1. Execution Context MUST return to its default state when the Checks-deferrable Call nesting depth counter is decreased back to the default value of 0.
1. If the Checks-deferrable Call nesting depth counter is decreased to the value greater than 0, the Execution Context MAY not be in its default state.
1. Execution Context's Account on behalf of which current low-level call is being performed MUST be storing address(0) when Account and Vault Status Checks are in progress.
1. The Call target address MUST NOT be the EVC itself or the ERC-1820 registry.
1. If the Call target is the `msg.sender`, the EVC MUST allow the caller to set the Execution Context's on behalf of Account address to any arbitrary value for the time of the Call allow to proceed without authentication.
1. The Batch external call target MUST NOT be the EVC, ERC-1820 registry address or the msg.sender itself.
1. If there's only one enabled Controller Vault for an Account, only that Controller MUST be allowed to Impersonate the Account's call into any of its enabled Collateral Vaults. Neither the Controller nor Collateral Vault can be the EVC.
1. The Controller Vault MUST NOT be allowed to use Permit message in order to Impersonate.
1. If there's only one enabled Controller Vault for an Account, only that Controller MUST be allowed to forgive the Account Status Check if it's deferred.
1. EVC MUST allow a Vault to forgive the Vault Status Check for itself if it's deferred.
1. Forgiven Account and Vault Status Checks will not be performed when the Checks-deferrable Call nesting depth counter is decreased back to 0, unless they are required again after the forgiveness.
1. Only the Checks-Deferrable Calls MUST allow to re-enter the EVC.
1. Simulation-related functions MUST NOT modify the state.

NOTE: In order to borrow, a user MUST enable a Controller. From then on, whenever the user wants to perform an action that may affect their solvency, the Controller MUST be consulted (the Account Status Check must be performed) in order to determine whether the action is allowed, or whether it should be blocked since it would make the account insolvent. The Account Status Check MUST be required on any operation which may affect Account's solvency. The EVC determines whether the check should be deferred or performed immediately.

NOTE: Enabling a Controller submits the account to the rules encoded in the Controller contract's code. All the funds in all enabled Collateral Vaults are now indirectly under control of the Controller Vault.

NOTE: Only the Controller can disable itself for the Account. This should typically happen upon an Account repaying its debt in full.

NOTE: The protocol deliberately doesn't enforce specific properties about the assets being used as collateral or liabilities. EVC users can therefore create vaults backed by irregular asset classes, such as NFTs, RWAs, uncollateralised IOUs, or synthetics.

NOTE: While it might be tempting for the Controller to allow a broad range of Collateral vaults to encourage borrowing, the Controller vault creators MUST exercise caution when deciding which vaults to accept as collateral. A malicious or incorrectly coded vault could, among other things, misrepresent the amount of assets it holds, reject liquidations when a user is in violation, or fail to require Account Status Checks when necessary. Therefore, vaults SHOULD limit allowed collaterals to a set of audited addresses known to be reliable, or verify the addresses in a registry or factory contract to ensure they were created by trustworthy, audited contracts.

NOTE: Accounts are fully isolated and can be treated as independent positions. Failing Account Status Check (ruled by enabled Controller Vault) may affect the ability to interact with the Account, including operations on the Vaults that are not enabled as Collaterals. In order to make the Account fully functional again, one MUST satisfy the Controller Vault conditions.

NOTE: Because the EVC contract can be made to invoke any arbitrary target contract with any arbitrary calldata, it SHOULD never be given any privileges, or hold any ETH or tokens.


## Vault Specification

1. A Vault MAY either only allow to be called through the EVC or MAY allow to be called both through the EVC and directly. When the Vault is called though the EVC, it MUST rely on `getCurrentOnBehalfOfAccount` function for the currently authenticated Account on behalf of which the operation is being performed. The Vault MUST consider this the true value of `msg.sender` for authorization purposes. If the Vault is called directly, the Vault MAY perform the authentication itself and OPTIONALLY use the `call` function on the EVC.
1. In more complex cases, to avoid status-check-related issues, it is advised to use the `call` function in the callback manner when the Vault is called directly. It will ensure the Account and Vault Status Checks are always deferred, at least until the end of the `call`.
1. `call` function SHALL only be used if `msg.sender` is not the EVC, in other words, if the Vault is called directly.
1. Before using `call` in the callback manner, the Vault is REQUIRED to authenticate the `msg.sender`. It is strongly advised to pass the `msg.sender` address as `onBehalfOfAccount` input of the `call` function unless there's a legitimate reason not to do so.
1. In order to support sub-accounts, operators, impersonation and permits, a Vault MUST be invoked via the EVC.
1. When a user requests to perform an operation such as borrow, a Vault MUST call into the EVC in order to ensure that the Account has enabled this Vault as a Controller. For that purpose `getCurrentOnBehalfOfAccount` or `isControllerEnabled` functions SHOULD be used.
1. Due to the fact that only the Controller can disable itself for the Account, a Vault MUST implement a standard `disableController` function that can be called by a user in order to disable the Controller if vault-specific conditions are met (typically, the Vault SHOULD check whether the Account has repaid its debt in full). If the vault-specific conditions are not met, the function MUST revert.
1. After each operation potentially affecting the Account's solvency (also on a non-borrowable Vault), a Vault MUST invoke the EVC in order to require the Account Status Check. The EVC determines whether the check should be deferred or performed immediately.
1. Vault MUST implement `checkAccountStatus` function which gets called for the accounts which have enabled this Vault as Controller. The function receives the Account address and the list of Collateral Vaults enabled for the Account. The function MUST determine whether or not the Account is in an acceptable state by returning the magic value or throwing an exception. If the Vault is deposit-only, the function SHOULD always return the appropriate magic value unless there's a need to implement custom logic.
1. `checkAccountStatus` is not called if there is no Controller enabled for the Account at the time of the checks, or when the only Controller was disabled before the checks are performed.
1. Vault MAY implement `checkVaultStatus` function which gets called if the Vault requires that via the EVC. The EVC determines whether the check should be deferred or performed immediately. This is an OPTIONAL functionality that allows the Vault to enforce its constraints (like supply/borrow caps, invariants checks etc.). If implemented, Vault Status Check MUST always be required by the Vault after each operation affecting the Vault's state. The `checkVaultStatus` function MUST determine whether or not the Vault is in an acceptable state by returning the magic value or throwing an exception. If the Vault doesn't implement this function, the Vault MUST NOT require the Vault Status Check.
1. In order to evaluate the Vault Status, `checkVaultStatus` MAY need access to a snapshot of the initial Vault state which SHOULD be taken at the beginning of the action that requires the check.
1. Both Account and Vault Status Check SHOULD be required at the very end of the operation.
1. The Controller MAY need to forgive the Account Status Check in order for the operation to succeed, i.e. during liquidations. However, the Account Status Check forgiveness MUST be done with care by ensuring that the forgiven Account's Status Check hadn't been deferred before the operation and that the call requiring the Account Status Check (i.e. Impersonation) does not perform any unexpected operations down the call path.
1. Vault MUST NOT allow calls to arbitrary contracts in uncontrolled manner, including the EVC.

NOTE: It may be tempting to allow a large set of collateral assets for a vault. However, vault creators MUST be careful about which assets they accept. A malicious vault could lie about the amount of assets it holds, or reject liquidations when a user is in violation. For this reason, vaults should restrict allowed collaterals to a known-good set of audited addresses, or lookup the addresses in a registry or factory contract to ensure they were created by known-good, audited contracts.

NOTE: There is a subtle complication that vault implementations should consider if they use re-entrancy guards (which is recommended). When a vault is invoked without Status Checks being deferred (i.e. vault called directly, not via the EVC), if it calls `require(Account|Vault)StatusCheck` on the EVC, the EVC will immediately call back into the vault's `check(Account|Vault)Status` function. A normal re-entrancy guard would fail upon re-entering at this point. To avoid this, vaults may wish to use the `call` EVC function or the vault implementation should relax the re-entrancy modifier to allow `check(Account|Vault)Status` call while invoking `require(Account|Vault)StatusCheck`.

NOTE: It MAY be critical to protect `check(Account|Vault)Status` functions against re-entrancy (depends on individual implementation). Additionally, the following check SHOULD be included as well: `require(msg.sender == address(evc) && evc.areChecksInProgress());`

NOTE: Care MUST be taken not to transfer any assets to the Accounts other than the Account Owner (ID 0). Otherwise, the assets may be lost. If unsure, a vault SHOULD call `getAccountOwner()` function that returns an address of the Account Owner if it's already registered on the EVC.

NOTE: If a vault attempted to read the collateral or controller sets of an account in order to enforce some policy of its own, then it is possible that a user could defer checks in a batch in order to be able to transiently violate them to satisfy the vault's policy. For this reason, vaults should not rely on the controller or collateral sets of an account if checks are deferred.


## Collateralized Borrowable Vault Implementation Guide

See the [diagrams](./diagrams) too!

### Deposit/mint considerations
1. Ensure re-entrancy protection
1. Authorize the appropriate account (the account from which the tokens will be pulled) depending on whether the vault is being called directly or through the EVC
1. Take the snapshot of the initial vault state if not taken yet in this context
1. Perform the operation
1. Require the Vault Status Check

### Withdraw/redeem considerations
1. Ensure re-entrancy protection
1. Authorize the appropriate account (the deposit owner or the account which was approved to withdraw/redeem) depending on whether the vault is being called directly or through the EVC
1. Take the snapshot of the initial vault state if not taken yet in this context
1. Perform the operation
1. Require the Account Status Check on the deposit owner
1. Require the Vault Status Check

### Borrow considerations
1. Ensure re-entrancy protection
1. Authorize the appropriate account (the account taking on the debt) depending on whether the vault is being called directly or through the EVC
1. Check whether the account taking on the debt has enabled the vault as a controller
1. Take the snapshot of the initial vault state if not taken yet in this context
1. Perform the operation
1. Require the Account Status Check on the account which took on the debt
1. Require the Vault Status Check

### Repay considerations
1. Ensure re-entrancy protection
1. Authorize the appropriate account (the account from which the tokens will be pulled) depending on whether the vault is being called directly or through the EVC
1. Take the snapshot of the initial vault state if not taken yet in this context
1. Perform the operation
1. Require the Vault Status Check

### Shares transfer considerations
1. Ensure re-entrancy protection
1. Authorize the appropriate account (the `from` account or the account which was approved to transfer) depending on whether the vault is being called directly or through the EVC
1. Take the snapshot of the initial vault state if not taken yet in this context
1. Perform the operation
1. Require the Account Status Check on the `from` account
1. Require the Vault Status Check

### Debt transfer considerations
1. Ensure re-entrancy protection
1. Authorize the appropriate account (the account which will receive the debt) depending on whether the vault is being called directly or through the EVC
1. Check whether the account which will receive the debt has enabled the vault as a controller
1. Take the snapshot of the initial vault state if not taken yet in this context
1. Perform the operation
1. Require the Account Status Check on the `to` account
1. Require the Vault Status Check

### Liquidation considerations
1. Ensure re-entrancy protection
1. Authorize the appropriate account (the liquidator account) depending on whether the vault is being called directly or through the EVC
1. Check whether the liquidator has enabled the vault as a controller
1. Ensure that the liquidator is not liquidating itself
1. Ensure that the violator does not have the Account Status Check deferred
1. Ensure that the collateral to be liquidated is recognized and trusted
1. Take the snapshot of the initial vault state if not taken yet in this context
1. Ensure that the violator is indeed in violation
1. Perform the operation
- Perform all the necessary calculations
- Decrease the violator's debt, increase the liquidator's debt
- Seize the collateral. If it's an internal balance, decrease the violator's balance and increase the liquidator's balance. If it's an external vault, use impersonation functionality to transfer the shares from the violator to the liquidator. After impersonation functionality used, forgive the Account Status Check on the violator
1. Require the Account Status Check on the liquidator account
1. Require the Vault Status Check

### Account Status Check considerations
1. Check whether it's the EVC calling
1. Check whether checks are in progress
1. Calculate the collateral and liability value
1. Return the magic value if the account healthy

### Vault Status Check considerations
1. Check whether it's the EVC calling
1. Check whether checks are in progress
1. Ensure that the snapshot status is valid
1. Compare the snapshot with the current vault state (invariant check, supply/borrow cap enforcement etc.)
1. Clear the old snapshot
1. Return the magic value if the vault healthy

### Other considerations
1. The vault MUST only be released from being a controller if the account has the debt fully repaid
1. The vault has freedom to implement the Account Status Check. It MAY price all the assets according to its preference, without depending on potentially untrustworthy oracles
1. The vault has freedom to implement the Vault Status Check. Depending on the implementation, the initial state snapshotting MAY not be needed. Depending on the implementation, not all the actions MAY require the Vault Status Check (i.e. vault share transfers). If snapshot is needed, note that it MAY require a prior vault state update (i.e. interest rate accrual). 
1. One SHOULD be careful when forgiving the Account Status Check after impersonation. A malicious target collateral could manipulate the impersonation process leading to a bad debt accrual. To prevent that, one MUST ensure that only trusted collaterals that behave in the expected way are being called using the impersonate functionality
1. When sending regular ERC20 tokens from a vault to an address, one SHOULD ensure that the address is not a sub-account but a valid EOA/contract address by getting an account owner from the EVC

### Typical implementation pattern of the EVC-compliant function for a vault

```solidity
function func() external routedThroughEVC nonReentrant {
    // retrieve the "true" message sender from the EVC. whether _msgSender or _msgSenderForBorrow should be called,
    // depends whether it's a debt-related functionality
    address msgSender = _msgSender();    // or _msgSenderForBorrow();

    // accrue the interest before the snapshot if it relies on it. otherwise it can be accrued after or never if 
    // the vault does not implement the interest accrual
    _accrueInterest();

    // take the snapshot if given functionality requires it
    takeVaultSnapshot();



    // CUSTOM FUNCTION LOGIC HERE



    // after all the custom logic has been executed, trigger the account status check and vault status check, if 
    // the latter one is needed. the account for which the account status check is required my differ and depends on 
    // the function logic. i.e.: 
    // - for shares transfer the `from` account should be checked 
    // - for debt transfer the `to` account should be checked
    // - for borrow the account taking on the debt should be checked
    // hence, the account checked is not always the `msgSender`
    requireAccountStatusCheck(account);
    requireVaultStatusCheck();
}
```

where `routedThroughEVC` can be implemented as follows:

```solidity
/// @notice Ensures that the msg.sender is the EVC by using the EVC call functionality if necessary.
modifier routedThroughEVC() {
    if (msg.sender == address(evc)) {
        _;
    } else {
        bytes memory result = evc.call(address(this), msg.sender, 0, msg.data);

        assembly {
            return(add(32, result), mload(result))
        }
    }
}
```

where `_msgSender` and `_msgSenderForBorrow` can be implemented as follows:

```solidity
/// @notice Retrieves the message sender in the context of the EVC.
/// @dev This function returns the account on behalf of which the current operation is being performed, which is
/// either msg.sender or the account authenticated by the EVC.
/// @return The address of the message sender.
function _msgSender() internal view returns (address) {
    address sender = msg.sender;

    if (sender == address(evc)) {
        (sender,) = evc.getCurrentOnBehalfOfAccount(address(0));
    }

    return sender;
}
```

```solidity
/// @notice Retrieves the message sender in the context of the EVC for a borrow operation.
/// @dev This function returns the account on behalf of which the current operation is being performed, which is
/// either msg.sender or the account authenticated by the EVC. This function reverts if the vault is not enabled as
/// a controller for the account on behalf of which the operation is being executed.
/// @return The address of the message sender.
function _msgSenderForBorrow() internal view returns (address) {
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
```