# Credit Vault Protocol

Mick de Graaf, Kasper Pawlowski, Dariusz Glowinski, Michael Bentley, Doug Hoyte

## Introduction

The Credit Vault Protocol (CVP) is an attempt to distill the core functionality required for a lending market into a minimal specification that can be used as a foundation for many diverse protocols. Assets are deposited into Credit Vaults, which are contracts that expose a standard ERC-4626 interface, as well as additional logic for interfacing with other vaults.

The CVP is primarily a mediator between Credit Vaults. In order to borrow from a vault, users must attach their accounts and various collateral vaults to this borrowed-from vault via the CVP. From then on, whenever a user wants to perform an action such as removing collateral, the liability vault (called controller) will be consulted in order to determine whether the action is allowed, or whether it should be blocked since it would make the account insolvent.

In addition to vault mediation, the CVP contains the functionality required to build flexible products, both for EOAs and smart contracts. Here are some of the benefits of building on the CVP:

* Batching. Multiple operations can be performed within a single batch operation, even those that concurrently affect multiple vaults. This is more convenient for UI users (no need for smart wallets), more gas efficient, and allows deferring liquidity check until the end of the batch (for flash rebalancing, setting up leveraged positions, etc)
* Simulations were a prized feature of the Euler V1 UI. The CVP exposes the optimal interface for simulating the effects of a set of operations and pre-visualising their effects in a UI.
* Sub-accounts were also a widely appreciated feature of Euler V1. They allowed users to create multiple isolated positions within their single parent account, and easily rebalance collateral/liabilities between them (no approvals needed). The CVP will allow users of any participating protocol to use sub-accounts, without requiring any special logic to be implemented by vaults.
* Operators allow users to attach external contracts to act on behalf of a sub-account. This is a generalisation of the E/DToken approval system and will unlock powerful functionality, even for EOAs. We have sketched out many possible use-cases to ensure that this system is fully general. For example, stop-loss/take-profit/trailing-stop/etc modifiers can be added to positions, or entire layered position managers can be built on top.
* The protocol deliberately doesn't enforce specific properties about the assets being used as collateral or liabilities. Protocol users can therefore create vaults backed by irregular asset classes, such as NFTs, uncollateralised IOUs, or synthetics.
* As well as the primary liquidity enforcement interface, there is an additional vault status check hook which allows vaults to enforce global-concern limits such as supply caps. These checks can also be deferred so that transient violations that are gone at the end of the transaction do not cause a failure.
* A common language for liquidations. If vaults choose, they can implement a core liquidation interface that will allow them to rely on an existing network of liquidators to keep their depositors safe.
* The CVP has been carefully designed to support nested vaults without exposing a reentrancy-based attack surface. This will allow Credit Vaults to be used as the underlying asset for other Credit Vaults. Among other things, this will provide the basis for a "base yield" feature of Euler V2 where a low-risk assets can optionally be used as components of higher-yielding products.

As well as providing the above features to a common base ecosystem, their re-use also keeps a substantial amount of complexity to be kept out of the core lending/borrowing contracts, leaving them free to focus on their differentiating factors such as pricing and risk management.



## Controller

The primary task of the CVP is to maintain a user's voluntary association with vaults. Typically, a user will deposit funds into one or more collateral vaults, and call `enableCollateral` for each that is indended to be used as a collateral, which adds the vault to the given account's collateral set. Users should obviously be careful which vaults they deposit to, since a malicious vault could refuse to return their funds.

After simply depositing, the user is not obligated or bound in any way by the CVP, and could freely withdraw funds from the vaults and/or `disableCollateral` to remove them from the account's collateral set.

However, suppose a user wants to take out a borrow from a separate vault. In this case, the user must call `enableController` to add this vault to the account's controller set. This is a significant action because the user is now entirely submitting the account to the rules encoded in the controller vault's code. All the funds in all the collateral vaults are now indirectly under control of the controller vault. In particular, if a user attempts to withdraw collateral or `disableCollateral` to remove a vault from the collateral set, the controller could cause the transaction to fail. Moreover, the controller can allow the collateral to be seized in order to repay the debt, using the `callFromControllerToCollateral` functionality described below.

* When requested to perform an action such as borrow, a liability vault must call into the CVP's `isControllerEnabled` function to ensure that the account has in fact enabled the vault as a controller.
* Only the controller itself can call `disableController` on the CVP. This should typically happen upon an account repaying its debt in full. Vaults must be coded carefully to not have edge cases such as unrepayable dust, otherwise accounts could become permanently associated with a controller.


## Account Status Checks

Account status checks are implemented by vaults to enforce liquidity checks. Vaults should expose an external view `checkAccountStatus` function that will receive an account and this account's list of enabled collaterals. If the account has not borrowed anything from this vault then this function should return `true`. Otherwise, the vault should evaluate application-specific logic to determine whether or not the account is in an acceptable state, either returning `true` or failing by returning `false` (or throwing an exception).

### Collateral Validity

Vaults should inspect the provided list of collaterals and determine whether or not they are acceptable. Vaults can limit themselves to a small set of collateral, or can be more general-purpose and allow borrowing using any assets they can get prices for. Alternately, a vault could always fail, if it is only intended to be a collateral vault.

To encourage borrowing, it may be tempting to allow a large set of collateral assets. However, vault creators must be careful about which assets they accept. A malicious vault could lie about the amount of assets it holds, or reject liquidations when a user is in violation. For this reason, vaults should restrict allowed collaterals to a known-good set of audited addresses, or lookup the addresses in a registry or factory contract to ensure they were created by known-good, audited contracts.

### Execution Flow

Although the vaults themselves implement `checkAccountStatus`, there is no need for them to invoke this function directly. It will be called by the CVP when necessary. Instead, after performing any operation that could affect an account's liquidity, a vault should invoke `requireAccountStatusCheck` on the CVP. Additionally, operations that can affect the liquidity of a *separate* account will need their own `requireAccountStatusCheck` calls.

Upon `requireAccountStatusCheck` call, the CVP will determine whether the current execution context is in a batch and if so, it will defer checking the status for this account until the end of the execution context. Otherwise, the account status check will be performed immediately.

There is a subtle complication that vault implementations should consider if they use reentrancy guards (which is recommended). When a vault is invoked *without* account status checks being deferred (ie, directly, not via the CVP), then when it calls `requireAccountStatusCheck` on the CVP, the CVP may immediately call back into the vault's `checkAccountStatus` function. A normal reentrancy guard would fail upon re-entering at this point. Because of this, the vault reference implementation relaxes the reentrancy modifier to allow `checkAccountStatus` call while invoking `requireAccountStatusCheck`.



## Vault Status Checks

Some vaults may have constraints that should be enforced globally. For example, supply and/or borrow caps that restrict the maxium amount of assets that can be supplied or borrowed, as a risk minimisation.

It does not necessarily make sense to enforce these checks when checking account status. First of all, if many accounts are affected within a batch, checking these global constraints each time would be redundant.

Secondly, some types of checks require an initial snapshot of the vault state before any operations have been performed. In the case of a borrow cap, it could be that the borrow cap has been exceeded for some reason (perhaps due to a price movement, or the borrow cap itself was reduced). The vault would still want to permit repaying debts, even if the repay was insufficient to bring the total borrows below the borrow cap.

To implement this, vaults should expose an extenal `checkVaultStatus` function. The vault should evaluate application-specific logic to determine whether or not the vault is in an acceptable state, either returning `true` or failing by returning `false` (or throwing an exception).

Although the vaults themselves implement `checkVaultStatus`, there is no need for them to invoke this function directly. It will be called by the CVP when necessary. Instead, after performing any operation that could affect vault's status, a vault should invoke `requireVaultStatusCheck` on the CVP. 

Upon `requireVaultStatusCheck` call, the CVP will determine whether the current execution context is in a batch and if so, it will defer checking the status for this vault until the end of the execution context. Otherwise, the vault status check will be performed immediately.

Considering the fact that in order to evaluate the vault status, the `checkVaultStatus` may need an access to the snapshot of the initial vault state, it is recommended to implement the following pattern which can be looked up in the reference vault implementation:
* each action that requires a vault status check, should first make an appropriate snapshot and store the data in the transient storage
* `checkVaultStatus` should evaluate the vault status by unpacking the snapshot data stored in the transient storage and compare it against current state of the vault, and return `false` (or revert) if there is a violation.

As with the account status check, there is a subtle complication that vault implementations should consider if they use reentrancy guards (which is recommended). When a vault is invoked *without* vault status checks being deferred (ie, directly, not via the CVP), then when it calls `requireVaultStatusCheck` on the CVP, the CVP may immediately call back into the vault's `checkVaultStatus` function. A normal reentrancy guard would fail upon re-entering at this point. Because of this, the vault reference implementation relaxes the reentrancy modifier to allow `checkVaultStatus` call while invoking `requireVaultStatusCheck`.


## Execution

### Batches

At the time of this writing, public/private keypair Ethereum accounts (EOAs) cannot directly perform multiple operations within a single transaction, except by invoking a smart contract that will do so on their behalf. The CVP exposes a `batch` function that allows multiple operations to be executed together. This has several advantages for users:

* Atomicity: The user knows that either all of the operations in a batch will execute, or none of them will, so there is no risk of being left with partial or inconsistent positions.
* Gas savings: If contracts are invoked multiple times, then the cost of "cold" access can be amortised across all of the invocations.
* Status check deferrals: Sometimes it is more convenient or efficient to perform some operation that would leave an account/vault in an invalid state, but fix this state in a subsequent operation in a batch. For example, you may want to borrow and swap *before* you deposit your collateral. With batches, these checks can be performed once at the end of a batch (which can also itself be more gas efficient).

### Authorisation

Inside each batch item, an `onBehalfOfAccount` can be specified. The `batch` function will determine whether or not `msg.sender` is authorised to perform operations on this account:

* If they share the first 19 bytes, then `onBehalfOfAccount` is considered to be a *sub-account* of `msg.sender` and therefore `msg.sender` is authorised.
* If `onBehalfOfAccount` is `address(0)` then it is considered to be `msg.sender` and is therefore authorised (this is a calldata gas optimisation)
* If the `onBehalfOfAccount` has previously had `setAccountOperator` called to install `msg.sender` as an *operator* for this account, it is authorised.
* In all other cases, the the batch item is invalid, and the entire batch transaction will fail unless batch item allows for failure.

#### Sub-Accounts

Sub-accounts allow users access to multiple (up to 256) virtual accounts that are entirely isolated from one another. Although multiple separate Ethereum addresses could be used, sub-accounts are often more efficient and convenient because their operations can be grouped together in a batch without setting approvals.

Since an account can only have one controller at a time (except for mid-transaction), sub-accounts are also the only way an Ethereum account can hold multiple borrows concurrently.

#### Operators

Operators are a more flexible and powerful version of approvals. While in effect, the operator contract can act on behalf of the specified account. This includes interacting with vaults (ie, withdrawing/borrowing funds), enabling vaults as collateral, etc. Because of this, it is recommended that only trusted and audited contracts, or an EOA held by a trusted individual, be installed as an operator.

Operators have many use cases. For instance, a user might want to install a modifier such as stop-loss/take-profit/trailing-stop to a position in an account. To accomplish this, special operator contract that allows "keepers" to close out the user's position when certain conditions are met can be installed. Multiple operators can be installed per account.

An operator is similar to a controller, in that an account gives considerable permissions to a smart contract (that presumably has been well audited). However, the important difference is that an account owner can always revoke an operator's privileges at any time, however they can not do so with a controller. Instead, the controller must release its own privileges. Another difference is that controllers can not change the account's collateral or controller sets, whereas an operator can.


### call

The `call` function on the Conductor allows users to invoke functions on vaults and other target smart contracts. Unless the `msg.sender` is the same as the `onBehalfOfAccount`, users *must* go through this function. This is because vaults themselves don't understand sub-accounts or operators, and only need to verify that they are being invoked by the conductor (see the FIXME section).

`call` also allows users to invoke arbitrary contracts, with arbitrary calldata. These other contracts will see the conductor as `msg.sender`. For this reason, it is critical that the Conductor itself never be given any special privileges, or hold any token or ETH balances (except for a few corner cases where it is temporarily safe, see the ERC-777 section below FIXME).

Batches can be composed of calls to the Conductor itself, and external `execute` calls (when the `targetContract` is not the Conductor). Calling the conductor is how users can enable collateral from within a batch, for example.

Batches will often be a mixture of external calls, some of which call vaults and some of which call other unrelated contracts. For example, a user might withdraw from one vault, then perform a swap on Uniswap, and then deposit into another vault.


### forward

The `forward` function can only be used in one specific case: When a controller vault wants to invoke a function on a collateral vault on behalf of the account under its control. The typical use-case for this is a liquidation. The controller vault would detect that an account entered violation due to a price movement, and seize some of collateral asset to repay the debt.

This is accomplished is by the controller vault calling `forward` and passing the collateral vault as the target contract and the violator as `onBehalfOfAccount`. The controller would construct a `withdraw` call using the its own address as the `receiver`. The collateral vault does not need to know that the funds are being withdrawn due to a liquidation.


### Execution Contexts

As mentioned above, when interacting with the Conductor, it is often useful to defer certain checks until the end of the transaction. This allows a user to temporarily violate some of the constraints imposed by the vaults being interacted with, so long as the constraints are satisfied at the end of the transaction.

In order to implement this, `batch` creates an *execution context* which maintains two sets of addresses in regular or transient storage (if supported): `accountStatusChecks` and `vaultStatusChecks`. The execution context will also contain the `onBehalfOfAddress` that has currently been authenticated, so it can be queried for by a vault (see security considerations).

An execution context will exist for the duration of the batch, and then be discarded. Only one execution context can exist at a time. However, nesting batches *is* allowed, because the execution context stores a "depth" value that increases each time a batch is started and decreases when it ends. Only once it decreases to the initial value do the deferred checks get performed. Nesting batches is useful because otherwise calling contracts from a batch that themselves want to defer checks would be more complicated, and these contracts would need two code-paths: one that defers and one that doesn't.

When the execution context is complete, the address sets are iterated over:

* For each address in `accountStatusChecks`, confirm that at most one controller is installed (its `accountControllers` set is of size 0 or 1). If a controller is installed, invoke `checkAccountStatus` on the controller for this account and ensure that the controller is satisfied.
* For each address in `vaultStatusChecks`, call `vaultStatusHook` (providing the initial snapshot data for this vault) and determine that the vault is satisfied.


### Simulations

The Conductor also supports executing batches in a "simulation" mode. This is only intended to be invoked "off-chain", and is useful for user interfaces because the can show the user what the expected outcome will be of a sequence of operations.

Simulations work by actually performing the requested operations but then reverting, which (if called on-chain) reverts all the effects. Although simple in principle, there are a number of design elements involved:

* Intermediate read-only queries can be inserted into a batch to gather simulated data useful for display
* The results are available even if status checks would cause a failure, for example so that a user can see exactly what is causing the failure
* Although internally simulations work by reverting, the recommended interface returns it as regular return data, which causes fewer compatibility problems (sometimes error data is mangled or dropped). This is the reason for `batchRevert`: You can't do a "try/catch" without an external call, so this must be an external function, although we recommend using the `batchSimulation` entry point instead.
* Simulations don't have the side-effect of making regular batches create large return-data (which would be gas inefficient)




## Security Considerations

### Authentication by Vaults

In order to support sub-accounts, operators, and forwarding (ie, liquidations), vaults can be invoked via the Conductor's `execute` function (or a batch), which will then execute the requested call on the vault. However, in this case the vault will see the Conductor as the `msg.sender`.

When a vault detects that `msg.sender` is the Conductor, it should call back into the conductor to retrieve the current execution context using `getExecutionContext`. This will tell the vault two things:

* The `onBehalfOfAddress` that has been authenticated by the conductor. The vault should consider this the "true" value of `msg.sender` for authorisation purposes.
* Whether or not account/market status checks have been deferred. If they have, then as an optimisation the market status checks and the `requireAccountStatusCheck` call to the conductor for the `onBehalfOfAddress` (but no other addresses) can be omitted.

If the vault is performing an operation (such as a borrow) that requires it to be the controller for an account, then the `getExecutionContextExtended` function can instead be invoked on the conductor. This requires an `account` argument and will returns both the items above, but also:

* A boolean `controllerEnabled` which is true only if the provided `account` argument has the vault in its controller set.

### Conductor Contract Privileges

Because the Conductor contract can be made to invoke any arbitrary target contract with any arbitrary calldata, it should never be given any privileges, or hold any ETH or tokens.

The only exception to this is mid-transaction inside of a batch. If one batch item temporarily moves ETH or tokens into the conductor, but a subsequent batch item moves it out, then because batches execute atomically, it is safe. However, generally moving tokens to the conductor is not necessary, because tokens can usually be moved immediately to their final destination with `transferFrom` etc.

One exception to this is wrapping ETH into WETH. The deposit method will always credit the caller with the WETH tokens. In this case, the user must transfer the WETH in a subsequent batch item.

One area where the untrustable conductor address may cause problems is tokens that implement hooks/callbacks, such as ERC-777 tokens. In this case, somebody could install a hook for the Conductor as a recipient, and cause inbound transfers to fail, or possibly even be redirected. Although the CVP doesn't attempt to comprehensively solve this, specifically for ERC-777 tokens and related systems, the ERC-1820 registry address is blocked and can not be invoked via `execute` or batches.







-- FIXME --
read-only re-entrancy protections: notInDeferral
Transient storage base class
maxWithdraw - can fail if pool not avail
you can have multiple controllers, but only mid-transaction
accountStatusCheck vs checkAccountStatus: names are confusing
