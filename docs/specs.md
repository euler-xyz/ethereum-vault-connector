# Credit Vault Connector (CVC) Protocol and Credit Vault (CV) Specification

## Definitions

- Credit Vault Connector (CVC): A smart contract that mediates between Credit Vaults in order to enable their lending and borrowing functionality.
- Credit Vault (CV): A smart contract that accepts deposits of a single asset and issues shares in return, may support borrowing functionality. It implements the logic and interface necessary for interaction with other Credit Vaults via CVC. It may be ERC-4626 compliant.
- Account: Every Ethereum address has 256 accounts in the CVC (one private key to rule them all). Each account has an account ID from 0-255. In order to compute the account addresses, the account ID is treated as a uint and XORed (exclusive ORed) with the Ethereum address. Effectively, a group of 256 accounts belonging to the same owner share the first 19 bytes of their address and differ only in the last byte.
- Account Owner: An EOA or smart contract Ethereum address, one of 256 accounts (account ID 0), that has ownership over the group of 256 accounts.
- Account Operator: An EOA or smart contract Ethereum address that has been granted permission to operate on behalf of an Account. The permission can only be granted by the Account Owner.
- Collateral Vault: A Credit Vault which deposits are used as collateral for borrowing in other Credit Vaults. An Account can enable up to 20 collaterals. Enabled collateral can be seized in case of liquidation.
- Controller Vault: A Credit Vault enabled by a user in order to be able to borrow from it. Enabling Controller submits the Account to the rules encoded in the Controller Vault's code. All the funds in all the enabled Collateral Vaults are indirectly under control of the Controller Vault. Whenever a user wants to perform an action such as removing collateral, the Controller Vault is consulted in order to determine whether the action is allowed, or whether it should be blocked since it would make the Account insolvent. An Account can have only one Controller Vault enabled at a time unless it's a transient state during batch execution.
- Batch: A list of operations that are executed atomically one by one. A batch defers Account and Vault Status Checks until the end of the transaction.
- Account Status Check: Functionality implemented by Credit Vaults to enforce Account solvency. Vaults should expose a special function that will receive an Account and this Account's list of enabled Collateral Vaults in order to determine the Account's liquidity status. Account status is checked immediately or is deferred until the end of the transaction if the operation is part of a batch. Accouns Status Check deferral allows for transient violation of Account solvency.
- Vault Status Check: Functionality implemented by Credit Vaults to enforce Vault contraints (i.e. supply/borrow caps). Vaults should expose a special function that should implement necessary checks in order to determine acceptable state of the Vault. Vault status is checked immediately or is deferred until the end of the transaction if the operation is part of a batch. Vault Status Check deferral allows for transient violation of Vault constraints.


## Credit Vault Connector (CVC) Specification

1. An Owner of the group of 256 accounts is recorded only once upon the first interaction of any of the accounts with the CVC.
1. Only an Account Owner can grant permission to an Account Operator to operate on behalf of the Account.
1. An Account can have multiple Account Operators.
1. Each Account can have at most 20 Collateral Vaults enabled at a time.
1. Each Account can have at most one Controller Vault enabled at a time unless it's a transient state during a batch execution. This is how single-liability-per-account is enforced.
1. Only an Account Owner or the Account Operator can enable and disable a Collateral Vault for the Account.
1. Only an Account Owner or the Account Operator can enable a Controller Vault for the Account.
1. Only a Controller Vault can disable itself for the Account.
1. Only an Owner or the Operator of the specified Account can call other contract through the CVC.
1. If there's only one enabled Controller Vault for an Account, only that Controller can impersonate the Account's call into any of its enabled Collateral Vaults.
1. CVC supports batches which are lists of operations executed atomically one by one. 
1. Batches can be nested up to 10 levels deep.
1. Inside each batch item, an Account is specified. The batch function determines whether or not `msg.sender` is authorised to perform operations on this Account.
1. CVC defers Account Status Checks and Vault Status Checks until the end of the transaction only if the operation requiring them is part of a batch. Otherwise they must be executed immediately.
1. Account Status Checks can be deferred for at most 20 Accounts at a time.
1. Vault Status Checks can be deferred for at most 20 Vaults at a time.
1. Deferred Account Status Checks and Vault Status Checks must be executed at the end of the transaction (after the top level batch is executed).
1. If there's only one enabled Controller Vault for an Account, CVC allows currently enabled Controller to forgive the Account Status Check if it's deferred.
1. CVC allows a Vault to forgive the Vault Status Check for itself if it's deferred.
1. Simulation functions must not modify the state.

NOTE: In order to borrow, a user must enable a Controller. From then on, whenever the user wants to perform an action that may affect thir solvency, the Controller must be consulted (the Account Status Check must be performed) in order to determine whether the action is allowed, or whether it should be blocked since it would make the account insolvent. The Account Status Check may be requested by the liability vault by calling the CVC which determines whether the check should be deferred until the very end of the transaction or performed immediately.

NOTE: Enabling a Controller submits the account to the rules encoded in the controller vault's code. All the funds in all enabled Collateral Vaults are now indirectly under control of the controller vault.

NOTE: Only the Controller can disable itself for the Account. This should typically happen upon an Account repaying its debt in full.

NOTE: The protocol deliberately doesn't enforce specific properties about the assets being used as collateral or liabilities. CVC users can therefore create vaults backed by irregular asset classes, such as NFTs, uncollateralised IOUs, or synthetics.

NOTE: Because the CVC contract can be made to invoke any arbitrary target contract with any arbitrary calldata, it should never be given any privileges, or hold any ETH or tokens.


## Credit Vault (CV) Specification

1. When user requests to perform an operation such as borrow, a Credit Vault must call into the CVC in order to ensure that the Account has enabled this vault as Controller. For that purpose `getExecutionContext` or `isControllerEnabled` functions can be used.
1. Due to the fact that only the Controller can disable itself for the Account, a Credit Vault must implement a standard `disableController` function that can be called by a user in order to disable the Controller for the Account if vault-specific conditions are met (typically, the vault must check whether the Account has its debt repaid in full).
1. After each operation affecting the Account's solvency, a Credit Vault must invoke CVC's `requireAccountStatusCheck` in order to request the Account Status Check. The CVC determines whether the check should be deferred until the very end of the transaction or performed immediately.
1. Credit Vault must implement `checkAccountStatus` function which gets called for the accounts which have enabled this vault as Controller. The function receives the Account and the list of Collateral Vaults enabled for the Account. The function must determine whether or not the Account is in an acceptable state, either returning `true` or failing by returning `false` (or throwing an exception). If the vault is deposit-only, the function should always return `true`.
1. Credit Vault may implement `checkVaultStatus` function which gets called if the vault calls `requireVaultStatusCheck` on the CVC. The CVC determines whether the check should be deferred until the very end of the transaction or performed immediately. This is an optional functionality that allows the vault to enforce its constraints (supply/borrow caps, invariants checks etc.). `checkVaultStatus` function must determine whether or not the Vault is in an acceptable state, either returning `true` or failing by returning `false` (or throwing an exception). If the vault doesn't implement this function, the vault musn't call the `requireVaultStatusCheck` function on the CVC.
1. In order to evaluate the Vault Status, `checkVaultStatus` may need access to a snapshot of the initial vault state which should be taken at the beginning of the action that requires the check.
1. Credit Vault may either be called directly or via the CVC. In order to support sub-accounts, operators and impersonating, vaults can be invoked via the CVC's `call`, `batch`, or `impersonate` functions, which will then execute the desired operations on the vault. However, in this case the vault will see the CVC as the `msg.sender`. When a vault detects that `msg.sender` is the CVC, it should call back into the CVC to retrieve current `onBehalfOfAccount` using `getExecutionContext`. `onBehalfOfAccount` indicates the account that has been authenticated by the CVC. The vault should consider this the true value of `msg.sender` for authorisation purposes.

NOTE: It may be tempting to allow a large set of collateral assets for a Credit Vault. However, vault creators must be careful about which assets they accept. A malicious Credit Vault could lie about the amount of assets it holds, or reject liquidations when a user is in violation. For this reason, vaults should restrict allowed collaterals to a known-good set of audited addresses, or lookup the addresses in a registry or factory contract to ensure they were created by known-good, audited contracts.

NOTE: There is a subtle complication that Credit Vault implementations should consider if they use reentrancy guards (which is recommended). When a vault is invoked without Status Checks being deferred (i.e. vault called directly, not via the CVC), then when it calls `require(Account|Vault)StatusCheck` on the CVC, the CVC may immediately call back into the vault's `check(Account|Vault)Status` function. A normal reentrancy guard would fail upon re-entering at this point. Because of this, the vault implementation should relax the reentrancy modifier to allow `check(Account|Vault)Status` call while invoking `require(Account|Vault)StatusCheck`.

NOTE: It is critical to protect `check(Account|Vault)Status` function against reentrancy as it may get called mid-operation when the state of the vault is not consistent, i.e. `require(Account|Vault)StatusNow` function may get called by ERC-777 hook on transfer leading to the immediate call of `check(Account|Vault)Status` in the middle of the operation.

NOTE: Care should be taken not to transfer any assets to the Accounts other than the Account Owner (ID 0). Otherwise, the assets may be lost forever.

NOTE: If a Credit Vault attempted to read the Collateral or Controller states of an Account on the CVC in order to enforce some policy of its own, then it is possible that a user could defer checks in a batch in order to be able to transiently violate them to satisfy the Credit Vault's policy. For this reason, Credit Vaults should not rely on the Controller or Collateral sets of an Account if checks are deferred.
