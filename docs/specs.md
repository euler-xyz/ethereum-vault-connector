# Ethereum Vault Connector and Vault Specification

## Definitions

- Ethereum Vault Connector (EVC): A smart contract that mediates between Vaults in order to enable their lending and borrowing functionality.
- Vault: A smart contract that accepts deposits of a single asset and issues shares in return, it may support borrowing functionality. It implements the logic and interface necessary for interaction with other Vaults via the EVC. Optionally, ERC-4626 compliant.
- Account: Every Ethereum address has 256 accounts in the EVC (one private key to rule them all). Each account has an account ID from 0-255. In order to compute the account addresses, the Account ID is treated as a uint and XORed (exclusive ORed) with the Ethereum address. Effectively, a group of 256 Accounts belonging to the same owner share the first 19 bytes of their address and differ only in the last byte.
- Account Owner: An EOA or a smart contract Ethereum address, one of the 256 Accounts with Account ID 0, that has ownership over the whole group of Accounts.
- Account Operator: An EOA or smart contract Ethereum address that has been granted a permission to operate on behalf of the Account. The permission can only be granted by the Account Owner.
- Collateral Vault: A Vault which deposits are recognized as collateral for borrowing in other Vaults. An Account can enable up to 20 collaterals. Enabled collateral can be seized by the Controller Vault in case of liquidation.
- Controller Vault: A Vault enabled by a user in order to be able to borrow from it. Enabling Controller submits the specified Account to the rules encoded in the Controller Vault's code. All the funds in all the enabled Collateral Vaults are indirectly under control of the Controller Vault. Whenever a user wants to perform an action such as removing collateral, the Controller Vault is consulted in order to determine whether the action is allowed, or whether it should be blocked since it would make the Account insolvent. An Account can have only one Controller Vault enabled at a time unless it's a transient state during checks deferral.
- Permit: An EIP-712 typed data message allowing arbitrary calldata execution on the EVC on behalf of the signer (Account Owner or Account Operator) of the message. It is useful for implementing "gasless" transactions.
- Callback: A functionality allowing the msg.sender to be called back by the EVC with the specified calldata and specified context set. The callback is executed with Account and Vault Status Checks deferred.
- Call: A functionality allowing an Account Owner or Account Operator to execute an arbitrary calldata on behalf of the specified Account while Account and Vault Status Checks are deferred.
- Impersonation: A functionality allowing an enabled Controller Vault to execute an arbitrary calldata on any of the enabled Collateral Vaults on behalf of the specified Account while Account and Vault Status Checks are deferred. The Controller Vault must be the only enabled Controller Vault for the Account in order to be able to impersonate the Account. Impersonation is useful for liquidation flows.
- Batch: A list of operations that are executed atomically one by one with Account and Vault Status Checks deferred.
- Simulation: An entry point into the EVC that allows for simulating the execution of a batch without modifying the state. It is useful for inspecting the outcome of a batch before executing it.
- Account Status Check: A functionality implemented by Vaults to enforce Account solvency. Vaults must expose a special function that will receive an Account address and this Account's list of enabled Collateral Vaults in order to determine the Account's liquidity status. Account status is checked immediately or is deferred until the end of the top-level call. Account Status Check deferral allows for a transient violation of the Account solvency.
- Vault Status Check: A functionality implemented by Vaults to enforce Vault constraints (i.e. supply/borrow caps). Vaults may expose a special function that implements necessary checks in order to determine acceptable state of the Vault. Vault status is checked immediately or is deferred until the end of the top-level call. Vault Status Check deferral allows for a transient violation of the Vault constraints.
- Checks-deferrable Call: Any of the function calls that defers the Account and Vault Status Checks, namely: Callback, Call, Impersonation, or Batch call. Checks-deferrable Calls can be nested.
- Checks Deferral: A functionality allowing to defer Account and Vault Status Checks until the end of the top-level Checks-deferrable Call. This allows for a transient violation of the Account solvency or Vault constraints.
- Execution Context: A data structure maintained by the EVC which holds information about current execution state. It tracks the checks-deferrable calls depth, currently authenticated Account address on behalf of which current operation is being performed, a flag indicating whether the account/vault status checks are in progress, a flag indicating whether the impersonation is in progress, a flag indicating whether an operator is currently operating on behalf of account and a flag indicating whether the simulation is in progress.


## Ethereum Vault Connector Specification

1. An Owner of the group of 256 accounts is recorded only once upon the first interaction of any of its accounts with the EVC.
1. Only an Account Owner can authorize an Account Operator to operate on behalf of the Account.
1. An Account can have multiple Account Operators.
1. Each Account can have at most 20 Collateral Vaults enabled at a time.
1. Each Account can have at most one Controller Vault enabled at a time unless it's a transient state during a Checks-deferrable Call. This is how single-liability-per-account is enforced.
1. Only an Account Owner or the Account Operator can enable and disable Collateral Vaults for the Account.
1. Only an Account Owner or the Account Operator can enable Controller Vaults for the Account.
1. Only an enabled Controller Vault can disable itself for the Account.
1. EVC supports signed Permit messages that allow anyone to execute arbitrary calldata on the EVC that was signed by the Account Owner or Account Operator.
1. EVC supports the following Checks-deferrable Call functions: Callback, Call, Impersonate and Batch that allow to call external contracts.
1. Each Checks-deferrable Call function specifies an Account. The functions determine whether or not `msg.sender` is authorised to perform operations on this Account. Only an Owner or an Operator of the specified Account can call other contract on behalf of the Account through the EVC.
1. EVC allows to defer Account and Vault Status Checks until the end of the top-level Checks-deferrable Call. That allows for a transient violation of the Account solvency or Vault constraints.
1. If the execution is not within a Checks-deferrable Call, Account and Vault Status Checks must be performed immediately.
1. Checks-deferrable Call can be nested up to 10 levels deep.
1. Account Status Checks can be deferred for at most 20 Accounts at a time.
1. Vault Status Checks can be deferred for at most 20 Vaults at a time.
1. EVC maintains the Execution Context observable by the external contracts.
1. The Callback cannot be executed within the Permit context.
1. The Call target cannot be the EVC, ERC-1820 registry address or the msg.sender itself
1. If there's only one enabled Controller Vault for an Account, only that Controller can Impersonate the Account's call into any of its enabled Collateral Vaults.
1. If there's only one enabled Controller Vault for an Account, EVC allows currently enabled Controller to forgive the Account Status Check if it's deferred.
1. EVC allows a Vault to forgive the Vault Status Check for itself.
1. Simulation-related functions do not modify the state.

NOTE: In order to borrow, a user must enable a Controller. From then on, whenever the user wants to perform an action that may affect their solvency, the Controller must be consulted (the Account Status Check must be performed) in order to determine whether the action is allowed, or whether it should be blocked since it would make the account insolvent. The Account Status Check may be requested by the liability vault by calling the EVC which determines whether the check should be deferred until the very end of the top-level checks-deferrable call (if applicable) or performed immediately.

NOTE: Enabling a Controller submits the account to the rules encoded in the Controller contract's code. All the funds in all enabled Collateral Vaults are now indirectly under control of the Controller Vault.

NOTE: Only the Controller can disable itself for the Account. This should typically happen upon an Account repaying its debt in full.

NOTE: The protocol deliberately doesn't enforce specific properties about the assets being used as collateral or liabilities. EVC users can therefore create vaults backed by irregular asset classes, such as NFTs, uncollateralised IOUs, or synthetics.

NOTE: Accounts are fully isolated and can be treated as independent positions. Failing Account Status Check (ruled by enabled Controller Vault) may affect the ability to interact with the Account, including operations on the Vaults that are not enabled as Collaterals. In order to make the Account fully functional again, one must satisfy the Controller Vault's conditions.

NOTE: Because the EVC contract can be made to invoke any arbitrary target contract with any arbitrary calldata, it should never be given any privileges, or hold any ETH or tokens.


## Vault Specification

1. A Vault can either only allow to be called through the EVC or allow to be called both through the EVC and directly. When the Vault is called though the EVC, it should rely on `getCurrentOnBehalfOfAccount` function for the currently authenticated Account on behalf of which the operation is being performed. The Vault should consider this the true value of `msg.sender` for authorisation purposes. If the Vault is called directly, the Vault should perform the authentication itself and optionally use `callback` function on the EVC.
1. In more complex cases, to avoid status-check-related issues, it is advised to use the `callback` function when Vault is called directly. It will ensure the Account and Vault Status Checks are always deferred until the end of the top-level call.
1. In order to support sub-accounts, operators, impersonation and permits, a Vault must be invoked via the EVC.
1. When a user requests to perform an operation such as borrow, a Vault must call into the EVC in order to ensure that the Account has enabled this vault as a Controller. For that purpose `getCurrentOnBehalfOfAccount` or `isControllerEnabled` functions can be used.
1. Due to the fact that only the Controller can disable itself for the Account, a Vault must implement a standard `disableController` function that can be called by a user in order to disable the Controller for the Account if vault-specific conditions are met (typically, the vault must check whether the Account has repaid its debt in full).
1. After each operation potentially affecting the Account's solvency (also on non-borrowable Vault), a Vault must invoke the EVC in order to request the Account Status Check. The EVC determines whether the check should be deferred until the very end of the top-level checks-deferrable call (if applicable) or performed immediately.
1. Vault must implement `checkAccountStatus` function which gets called for the accounts which have enabled this vault as Controller. The function receives the Account address and the list of Collateral Vaults enabled for the Account. The function must determine whether or not the Account is in an acceptable state by returning the magic value or throwing an exception. If the vault is deposit-only, the function should always return the appropriate magic value.
1. Vault may implement `checkVaultStatus` function which gets called if the vault requests that via the EVC. The EVC determines whether the check should be deferred until the very end of the top-level checks-deferrable call (if applicable) or performed immediately. This is an optional functionality that allows the vault to enforce its constraints (like supply/borrow caps, invariants checks etc.). Vault Status Check must always be requested by the vault after each operation affecting the vault's state. The `checkVaultStatus` function must determine whether or not the Vault is in an acceptable state by returning the magic value or throwing an exception. If the vault doesn't implement this function, the vault mustn't request the Vault Status Check.
1. In order to evaluate the Vault Status, `checkVaultStatus` may need access to a snapshot of the initial vault state which should be taken at the beginning of the action that requires the check.
1. Both Account and Vault Status Check should be requested at the very end of the operation.
1. The Controller may need to forgive the Account Status Check in order for the operation to succeed, i.e. during liquidation. However, the Account Status Check forgiveness must be done with care by ensuring that the forgiven Account's Status Check hasn't been deferred before the operation and that the call requiring the Account Status Check (i.e. Impersonation) does not perform any unexpected operations down the call path.

NOTE: It may be tempting to allow a large set of collateral assets for a Vault. However, vault creators must be careful about which assets they accept. A malicious Vault could lie about the amount of assets it holds, or reject liquidations when a user is in violation. For this reason, vaults should restrict allowed collaterals to a known-good set of audited addresses, or lookup the addresses in a registry or factory contract to ensure they were created by known-good, audited contracts.

NOTE: There is a subtle complication that Vault implementations should consider if they use reentrancy guards (which is recommended). When a vault is invoked without Status Checks being deferred (i.e. vault called directly, not via the EVC), if it calls `require(Account|Vault)StatusCheck` (or similar) on the EVC, the EVC will immediately call back into the vault's `check(Account|Vault)Status` function. A normal reentrancy guard would fail upon re-entering at this point. To avoid this, vaults may wish to use the `callback` EVC function or the vault implementation should relax the reentrancy modifier to allow `check(Account|Vault)Status` call while invoking `require(Account|Vault)StatusCheck`.

NOTE: It may be critical to protect `check(Account|Vault)Status` functions against reentrancy (depends on individual implementation). Additionally, it is recommended to include the following check as well: `require(msg.sender == address(evc) && evc.areChecksInProgress());`

NOTE: Care should be taken not to transfer any assets to the Accounts other than the Account Owner (ID 0). Otherwise, the assets may be lost. If unsure, a vault may call `getAccountOwner()` function that returns an address of the Account Owner if it's already registered on the EVC.

NOTE: If a Vault attempted to read the Collateral or Controller sets of an Account in order to enforce some policy of its own, then it is possible that a user could defer checks in a batch in order to be able to transiently violate them to satisfy the Vault's policy. For this reason, Vaults should not rely on the Controller or Collateral sets of an Account if checks are deferred.


## Collateralized Borrowable Vault Implementation Guide

### Deposit/mint considerations
1. Ensure reentrancy protection
1. Authenticate the caller (the account from which the tokens will be pulled) depending on whether the vault is being called directly or through the EVC
1. Take the snapshot of the initial vault state if not taken yet in this context
1. Perform the operation
1. Require the Vault Status Check

### Withdraw/redeem considerations
1. Ensure reentrancy protection
1. Authenticate the caller (the deposit owner or the account which was approved to withdraw/redeem) depending on whether the vault is being called directly or through the EVC
1. Take the snapshot of the initial vault state if not taken yet in this context
1. Perform the operation
1. Require the Account Status Check on the deposit owner
1. Require the Vault Status Check

### Borrow considerations
1. Ensure reentrancy protection
1. Authenticate the caller (the account taking on the debt) depending on whether the vault is being called directly or through the EVC
1. Check whether the account taking on the debt has enabled the vault as a controller
1. Take the snapshot of the initial vault state if not taken yet in this context
1. Perform the operation
1. Require the Account Status Check on the account which took on the debt
1. Require the Vault Status Check

### Repay considerations
1. Ensure reentrancy protection
1. Authenticate the caller (the account from which the tokens will be pulled) depending on whether the vault is being called directly or through the EVC
1. Take the snapshot of the initial vault state if not taken yet in this context
1. Perform the operation
1. If the debt fully repaid, release the vault from being a controller of the account which used to have the debt
1. Require the Vault Status Check

### Shares transfer considerations
1. Ensure reentrancy protection
1. Authenticate the caller (the `from` account or the account which was approved to transfer) depending on whether the vault is being called directly or through the EVC
1. Take the snapshot of the initial vault state if not taken yet in this context
1. Perform the operation
1. Require the Account Status Check on the `from` account
1. Require the Vault Status Check

### Debt transfer considerations
1. Ensure reentrancy protection
1. Authenticate the caller (the account which will receive the debt) depending on whether the vault is being called directly or through the EVC
1. Check whether the account which will receive the debt has enabled the vault as a controller
1. Take the snapshot of the initial vault state if not taken yet in this context
1. Perform the operation
1. Release the vault from being a controller of the `from` account if the `from` account no longer has any debt
1. Require the Account Status Check on the `to` account
1. Require the Vault Status Check

### Liquidation considerations
1. Ensure reentrancy protection
1. Authenticate the caller (the liquidator account) depending on whether the Vault is being called directly or through the EVC
1. Check whether the liquidator has enabled the vault as a controller
1. Take the snapshot of the initial vault state if not taken yet in this context
1. Ensure that the liquidator is not liquidating itself
1. Ensure that the violator does not have the Account Status Check deferred
1. Ensure that the collateral to be liquidated is recognized and trusted
1. Ensure that the violator is indeed in violation
1. Perform the operation
- Perform all the necessary calculations
- Decrease the violator's debt, increase the liquidator's debt
- Seize the collateral. If it's an internal balance, decrease the violator's balance and increase the liquidator's balance. If it's an external vault, use impersonation functionality to transfer the shares from the violator to the liquidator. After impersonation functionality used, forgive the Account Status Check on the violator
1. Release the vault from being a controller of the violator if the position is fully liquidated
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
1. The vault can only be released from being a controller only if the acount has the debt fully repaid
1. The vault has freedom to execute the Account Status Check, allowing it to price all the assets according to its preference, without depending on potentially untrustworthy oracles
1. The vault has freedom to implement the Vault Status Check. Depending on the implementation, the initial state snapshotting might not be needed. Depending on the implementation, not all the actions may require the Vault Status Check (i.e. vault share transfers). If snapshot is needed, note that it might require a prior vault state update (i.e. interest rate accrual). 
1. One should be careful when forgiving the Account Status Check after impersonation. A malicious target collateral could manipulate the impersonation process leading to a bad debt accrual. To prevent that, ensure that only trusted collaterals that behave in the expected way are being called using the impersonate functionality
1. When sending regular ERC20 tokens from a vault to an address, one can ensure that the address is not a sub-account but a valid EOA/contract address by getting an account owner from the EVC
