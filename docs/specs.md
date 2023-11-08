# Ethereum Vault Connector and Vault Specification

## Definitions

- Ethereum Vault Connector (EVC): A smart contract that mediates between Vaults in order to enable their lending and borrowing functionality.
- Vault: A smart contract that accepts deposits of a single asset and issues shares in return, it may support borrowing functionality. It implements the logic and interface necessary for interaction with other Vaults via the EVC. Optionally, ERC-4626 compliant.
- Account: Every Ethereum address has 256 accounts in the EVC (one private key to rule them all). Each account has an account ID from 0-255. In order to compute the account addresses, the account ID is treated as a uint and XORed (exclusive ORed) with the Ethereum address. Effectively, a group of 256 accounts belonging to the same owner share the first 19 bytes of their address and differ only in the last byte.
- Account Owner: An EOA or a smart contract Ethereum address, one of the 256 accounts with account ID 0, that has ownership over the group of 256 accounts.
- Account Operator: An EOA or smart contract Ethereum address that has been granted a permission to operate on behalf of the Account. The permission can only be granted by the Account Owner.
- Collateral Vault: A Vault which deposits are recognized as collateral for borrowing in other Vaults. An Account can enable up to 20 collaterals. Enabled collateral can be seized by the Controller Vault in case of liquidation.
- Controller Vault: A Vault enabled by a user in order to be able to borrow from it. Enabling Controller submits the specified Account to the rules encoded in the Controller Vault's code. All the funds in all the enabled Collateral Vaults are indirectly under control of the Controller Vault. Whenever a user wants to perform an action such as removing collateral, the Controller Vault is consulted in order to determine whether the action is allowed, or whether it should be blocked since it would make the Account insolvent. An Account can have only one Controller Vault enabled at a time unless it's a transient state during checks deferral.
- Permit: An EIP-712 typed data message allowing arbitrary calldata execution on behalf of the signer (Account Owner or Account Operator) of the message. It is useful for implementing "gasless" transactions.
- Callback: A functionality allowing the msg.sender to be called back by the EVC with the specified calldata and specified context set. The callback is executed with Account and Vault Status Checks deferred.
- Call: A functionality allowing an Account Owner or Account Operator to execute an arbitrary calldata on behalf of the specified Account while Account and Vault Status Checks are deferred.
- Impersonation: A functionality allowing an enabled Controller Vault to execute an arbitrary calldata on any of the enabled Collateral Vaults on behalf of the specified Account while Account and Vault Status Checks are deferred. The Controller Vault must be the only enabled Controller Vault for the Account in order to be able to impersonate the Account. Impersonation is useful for liquidation flows.
- Batch: A list of operations that are executed atomically one by one with Account and Vault Status Checks deferred.
- Simulation: An entry point into the EVC that allows for simulating the execution of a batch without modifying the state. It is useful for inspecting the outcome of a batch before executing it.
- Account Status Check: A functionality implemented by Vaults to enforce Account solvency. Vaults must expose a special function that will receive an Account address and this Account's list of enabled Collateral Vaults in order to determine the Account's liquidity status. Account status is checked immediately or is deferred until the end of the top-level call. Account Status Check deferral allows for a transient violation of the Account solvency.
- Vault Status Check: A functionality implemented by Vaults to enforce Vault constraints (i.e. supply/borrow caps). Vaults may expose a special function that implements necessary checks in order to determine acceptable state of the Vault. Vault status is checked immediately or is deferred until the end of the top-level call. Vault Status Check deferral allows for a transient violation of the Vault constraints.
- Checks-deferrable Call: Any of the function calls that defers the Account and Vault Status Checks namely Callback, Call, Impersonation, or Batch call. Checks-deferrable Calls can be nested.
- Checks Deferral: A functionality allowing to defer Account and Vault Status Checks until the end of the top-level Checks-deferrable Call. This allows for a transient violation of the Account solvency or Vault constraints.


## Ethereum Vault Connector Specification

1. An Owner of the group of 256 accounts is recorded only once upon the first interaction of any of its accounts with the EVC.
1. Only an Account Owner can authorize an Account Operator to operate on behalf of the Account.
1. An Account can have multiple Account Operators.
1. Each Account can have at most 20 Collateral Vaults enabled at a time.
1. Each Account can have at most one Controller Vault enabled at a time unless it's a transient state during a checks deferral. This is how single-liability-per-account is enforced.
1. Only an Account Owner or the Account Operator can enable and disable Collateral Vaults for the Account.
1. Only an Account Owner or the Account Operator can enable Controller Vaults for the Account.
1. Only an enabled Controller Vault can disable itself for the Account.
1. Only an Owner or an Operator of the specified Account can call other contract on behalf of the Account through the EVC.
1. If there's only one enabled Controller Vault for an Account, only that Controller can impersonate the Account's call into any of its enabled Collateral Vaults.
1. EVC supports batches which are lists of operations executed atomically one by one. 
1. Inside each batch item, an Account is specified. The batch function determines whether or not `msg.sender` is authorised to perform operations on this Account.
1. EVC allows to defer Account and Vault Status Checks until the end of the top-level Checks-deferrable Call. That allows for a transient violation of the Account solvency or Vault constraints.
1. If the execution is not within a Checks-deferrable Call, Account and Vault Status Checks must be performed immediately.
1. Checks-deferrable Call can be nested up to 10 levels deep.
1. Account Status Checks can be deferred for at most 20 Accounts at a time.
1. Vault Status Checks can be deferred for at most 20 Vaults at a time.
1. If there's only one enabled Controller Vault for an Account, EVC allows currently enabled Controller to forgive the Account Status Check if it's deferred.
1. EVC allows a Vault to forgive the Vault Status Check for itself if it's deferred.
1. Simulation functions do not modify the state.
1. EVC allows anyone to execute arbitrary calldata that was signed by the Account Owner or Account Operator.

NOTE: In order to borrow, a user must enable a Controller. From then on, whenever the user wants to perform an action that may affect thir solvency, the Controller must be consulted (the Account Status Check must be performed) in order to determine whether the action is allowed, or whether it should be blocked since it would make the account insolvent. The Account Status Check may be requested by the liability vault by calling the EVC which determines whether the check should be deferred until the very end of the top-level checks-deferrable call (if applicable) or performed immediately.

NOTE: Enabling a Controller submits the account to the rules encoded in the Controller contract's code. All the funds in all enabled Collateral Vaults are now indirectly under control of the Controller Vault.

NOTE: Only the Controller can disable itself for the Account. This should typically happen upon an Account repaying its debt in full.

NOTE: The protocol deliberately doesn't enforce specific properties about the assets being used as collateral or liabilities. EVC users can therefore create vaults backed by irregular asset classes, such as NFTs, uncollateralised IOUs, or synthetics.

NOTE: Because the EVC contract can be made to invoke any arbitrary target contract with any arbitrary calldata, it should never be given any privileges, or hold any ETH or tokens.


## Vault Specification

1. When a user requests to perform an operation such as borrow, a Vault must call into the EVC in order to ensure that the Account has enabled this vault as a Controller. For that purpose `getCurrentOnBehalfOfAccount` or `isControllerEnabled` functions can be used.
1. Due to the fact that only the Controller can disable itself for the Account, a Vault must implement a standard `disableController` function that can be called by a user in order to disable the Controller for the Account if vault-specific conditions are met (typically, the vault must check whether the Account has repaid its debt in full).
1. After each operation affecting the Account's solvency, a Vault must invoke the EVC in order to request the Account Status Check. The EVC determines whether the check should be deferred until the very end of the top-level checks-deferrable call (if applicable) or performed immediately.
1. Vault must implement `checkAccountStatus` function which gets called for the accounts which have enabled this vault as Controller. The function receives the Account address and the list of Collateral Vaults enabled for the Account. The function must determine whether or not the Account is in an acceptable state by returning the magic value or throwing an exception. If the vault is deposit-only, the function should always return the appropriate magic value.
1. Vault may implement `checkVaultStatus` function which gets called if the vault requests that via the EVC. The EVC determines whether the check should be deferred until the very end of the top-level checks-deferrable call (if applicable) or performed immediately. This is an optional functionality that allows the vault to enforce its constraints (like supply/borrow caps, invariants checks etc.). Vault Status Check must always be requested by the vault after each operation affecting the vault's state. The `checkVaultStatus` function must determine whether or not the Vault is in an acceptable state by returning the magic value or throwing an exception. If the vault doesn't implement this function, the vault mustn't request the Vault Status Check.
1. In order to evaluate the Vault Status, `checkVaultStatus` may need access to a snapshot of the initial vault state which should be taken at the beginning of the action that requires the check.
1. Vault may either be called directly or via the EVC. In order to support sub-accounts, operators, impersonation and permits, vaults can be invoked via the EVC's `call`, `batch`, `impersonate`, or `permit` functions, which will then execute the desired operations on the vault. However, in this case the vault will see the EVC as the `msg.sender`. When a vault detects that `msg.sender` is the EVC, it should call back into the EVC to retrieve current `onBehalfOfAccount` using `getCurrentOnBehalfOfAccount()`. `onBehalfOfAccount` indicates the account that has been authenticated by the EVC. The vault should consider this the true value of `msg.sender` for authorisation purposes.
1. In more complex cases, to avoid status-check-related issues, vaults may choose to always be invoked via the EVC, or use the `callback` function when being called directly. It will ensure the Account and Vault Status Checks are always deferred until the end of the top-level call.

NOTE: It may be tempting to allow a large set of collateral assets for a Vault. However, vault creators must be careful about which assets they accept. A malicious Vault could lie about the amount of assets it holds, or reject liquidations when a user is in violation. For this reason, vaults should restrict allowed collaterals to a known-good set of audited addresses, or lookup the addresses in a registry or factory contract to ensure they were created by known-good, audited contracts.

NOTE: There is a subtle complication that Vault implementations should consider if they use reentrancy guards (which is recommended). When a vault is invoked without Status Checks being deferred (i.e. vault called directly, not via the EVC), then when it calls `require(Account|Vault)StatusCheck` (or similar) on the EVC, the EVC may immediately call back into the vault's `check(Account|Vault)Status` function. A normal reentrancy guard would fail upon re-entering at this point. Because of this, the vault implementation should relax the reentrancy modifier to allow `check(Account|Vault)Status` call while invoking `require(Account|Vault)StatusCheck`.

NOTE: It may be critical to protect `check(Account|Vault)Status` functions against reentrancy (depends on individual implementation). For abundance of caution it is recommended to include the following checks as well:
`require(msg.sender == address(evc) && evc.areChecksInProgress());`

NOTE: Care should be taken not to transfer any assets to the Accounts other than the Account Owner (ID 0). Otherwise, the assets may be lost. If unsure, a vault may call `getAccountOwner()` function that returns an address of the Account Owner.

NOTE: If a Vault attempted to read the Collateral or Controller sets of an Account in order to enforce some policy of its own, then it is possible that a user could defer checks in a batch in order to be able to transiently violate them to satisfy the Vault's policy. For this reason, Vaults should not rely on the Controller or Collateral sets of an Account if checks are deferred.
