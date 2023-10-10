# Credit Vault Connector (CVC) Protocol

Mick de Graaf, Kasper Pawlowski, Dariusz Glowinski, Michael Bentley, Doug Hoyte

<!-- TOC FOLLOWS -->
<!-- START OF TOC -->
* [Introduction](#introduction)
* [Controller](#controller)
* [Account Status Checks](#account-status-checks)
  * [Collateral Validity](#collateral-validity)
  * [Execution Flow](#execution-flow)
  * [Single Controller](#single-controller)
  * [Require Immediate](#require-immediate)
  * [Forgiveness](#forgiveness)
* [Vault Status Checks](#vault-status-checks)
* [Execution](#execution)
  * [Batches](#batches)
  * [Authorisation](#authorisation)
    * [Sub-Accounts](#sub-accounts)
    * [Operators](#operators)
    * [Permit](#permit)
  * [call](#call)
  * [impersonate](#impersonate)
  * [Execution Contexts](#execution-contexts)
    * [Nested Execution Contexts](#nested-execution-contexts)
    * [checksLock](#checkslock)
    * [impersonateLock](#impersonatelock)
  * [Simulations](#simulations)
* [Transient Storage](#transient-storage)
* [Security Considerations](#security-considerations)
  * [Authentication by Vaults](#authentication-by-vaults)
  * [CVC Contract Privileges](#cvc-contract-privileges)
  * [Read-only Re-entrancy](#read-only-re-entrancy)
<!-- END OF TOC -->

## Introduction

The Credit Vault Connector (CVC) Protocol is an attempt to distill the core functionality required for a lending market into a minimal specification that can be used as a foundation for many diverse protocols. Assets are deposited into Credit Vaults, which are contracts that expose a standard ERC-4626 interface, as well as additional logic for interfacing with other vaults.

The CVC is primarily a mediator between Credit Vaults. In order to borrow from a vault, users must attach their accounts and various collateral vaults to this borrowed-from vault via the CVC. From then on, whenever a user wants to perform an action such as removing collateral, the liability vault (called controller) will be consulted in order to determine whether the action is allowed, or whether it should be blocked since it would make the account insolvent.

In addition to vault mediation, the CVC contains the functionality required to build flexible products, both for EOAs and smart contracts. Here are some of the benefits of building on the CVC:

* Batching. Multiple operations can be performed within a single batch operation, even those that concurrently affect multiple vaults. This is more convenient for UI users (no need for smart wallets), more gas efficient, and allows deferring liquidity check until the end of the batch (for flash rebalancing, setting up leveraged positions, etc)
* Simulations were a prized feature of the Euler V1 UI. The CVC exposes the optimal interface for simulating the effects of a set of operations and pre-visualising their effects in a UI.
* Sub-accounts were also a widely appreciated feature of Euler V1. They allowed users to create multiple isolated positions within their single parent account, and easily rebalance collateral/liabilities between them (no approvals needed). The CVC will allow users of any participating protocol to use sub-accounts, without requiring any special logic to be implemented by vaults.
* Operators allow users to attach external contracts to act on behalf of a sub-account. This is a generalisation of the E/DToken approval system and will unlock powerful functionality, even for EOAs. We have sketched out many possible use-cases to ensure that this system is fully general. For example, stop-loss/take-profit/trailing-stop/etc modifiers can be added to positions, or entire layered position managers can be built on top.
* The protocol deliberately doesn't enforce specific properties about the assets being used as collateral or liabilities. CVC users can therefore create vaults backed by irregular asset classes, such as NFTs, uncollateralised IOUs, or synthetics.
* As well as the primary liquidity enforcement interface, there is an additional vault status check hook which allows vaults to enforce global-concern limits such as supply caps. These checks can also be deferred so that transient violations that are gone at the end of the transaction do not cause a failure.
* A common language for liquidations. If vaults choose, they can implement a core liquidation interface that will allow them to rely on an existing network of liquidators to keep their depositors safe.
* The CVC has been carefully designed to support nested vaults without exposing a reentrancy-based attack surface. This will allow Credit Vaults to be used as the underlying asset for other Credit Vaults. Among other things, this will provide the basis for a "base yield" feature of Euler V2 where a low-risk assets can optionally be used as components of higher-yielding products.

As well as providing the above features to a common base ecosystem, their re-use also keeps a substantial amount of complexity to be kept out of the core lending/borrowing contracts, leaving them free to focus on their differentiating factors such as pricing and risk management.



## Controller

The primary task of the CVC is to maintain a user's voluntary association with vaults. Typically, a user will deposit funds into one or more collateral vaults, and call `enableCollateral` for each that is intended to be used as a collateral, which adds the vault to the given account's collateral set. Users should obviously be careful which vaults they deposit to, since a malicious vault could refuse to return their funds.

After simply depositing, the user is not obligated or bound in any way by the CVC, and could freely withdraw funds from the vaults and/or `disableCollateral` to remove them from the account's collateral set.

However, suppose a user wants to take out a borrow from a separate vault. In this case, the user must call `enableController` to add this vault to the account's controller set. This is a significant action because the user is now entirely submitting the account to the rules encoded in the controller vault's code. All the funds in all the collateral vaults are now indirectly under control of the controller vault. In particular, if a user attempts to withdraw collateral or `disableCollateral` to remove a vault from the collateral set, the controller could cause the transaction to fail. Moreover, the controller can allow the collateral to be seized in order to repay the debt, using the `impersonate` functionality described below.

* When requested to perform an action such as borrow, a liability vault must call into the CVC's `isControllerEnabled` function to ensure that the account has in fact enabled the vault as a controller.
* Only the controller itself can call `disableController` on the CVC. This should typically happen upon an account repaying its debt in full. Vaults must be coded carefully to not have edge cases such as unrepayable dust, otherwise accounts could become permanently associated with a controller.


## Account Status Checks

Account status checks are implemented by vaults to enforce liquidity checks. Vaults should expose an external `checkAccountStatus` function that will receive an account and this account's list of enabled collaterals. If the account has not borrowed anything from this vault then this function should return `true`. Otherwise, the vault should evaluate application-specific logic to determine whether or not the account is in an acceptable state, either returning `true` or failing by returning `false` (or throwing an exception).

### Collateral Validity

Vaults should inspect the provided list of collaterals and determine whether or not they are acceptable. Vaults can limit themselves to a small set of collateral, or can be more general-purpose and allow borrowing using any assets they can get prices for. Alternately, a vault could always fail, if it is only intended to be a collateral vault.

To encourage borrowing, it may be tempting to allow a large set of collateral assets. However, vault creators must be careful about which assets they accept. A malicious vault could lie about the amount of assets it holds, or reject liquidations when a user is in violation. For this reason, vaults should restrict allowed collaterals to a known-good set of audited addresses, or lookup the addresses in a registry or factory contract to ensure they were created by known-good, audited contracts.

### Execution Flow

Although the vaults themselves implement `checkAccountStatus`, there is no need for them to invoke this function directly. It will be called by the CVC when necessary. Instead, after performing any operation that could affect an account's liquidity, a vault should invoke `requireAccountStatusCheck` on the CVC. Additionally, operations that can affect the liquidity of a *separate* account will need their own `requireAccountStatusCheck` calls.

Upon `requireAccountStatusCheck` call, the CVC will determine whether the current execution context is in a batch and if so, it will defer checking the status for this account until the end of the execution context. Otherwise, the account status check will be performed immediately.

There is a subtle complication that vault implementations should consider if they use reentrancy guards (which is recommended). When a vault is invoked *without* account status checks being deferred (ie, directly, not via the CVC), then when it calls `requireAccountStatusCheck` on the CVC, the CVC may immediately call back into the vault's `checkAccountStatus` function. A normal reentrancy guard would fail upon re-entering at this point. Because of this, the vault reference implementation relaxes the reentrancy modifier to allow `checkAccountStatus` call while invoking `requireAccountStatusCheck`.

### Single Controller

At the time of the account status check, an account can have at most one controller. This is how single-liability-per-account is enforced. Multiple controllers would be more complicated to reason about, and it is unlikely two independent controllers would be able to behave consistently in the presence of a "shared" accounts. If this is ever required, a multi-controller controller can be created with the specific sharing logic desired.

Although having more than one controller is disallowed when the account status check is performed, multiple controllers can be transiently attached while these checks are deferred. As long as all or all but one controllers release themselves during the execution of the batch, the account status check will succeed.

### Require Immediate

Inside a batch, account status checks are defered and only checked at the end. However, in some cases it is desirable to immediately check an account's status using `requireAccountStatusCheckNow`. If the specified account has a controller, this vault's `checkAccountStatus` is immediately invoked to determine if the account has a valid status.

If valid, the account is removed from the account status deferal set (if present), so it will not be checked again at the end of the batch. However, any future operations in the same batch that require a (non-immediate) status check will re-add it to the set, and the status will be checked at the end of the batch.

Some use-cases are:

* If a vault wants to prevent providing flash loans for whatever reason, it can require the account be healthy immediately following a borrow.
* If a batch creator believes there is a possibility that an account will be unhealthy after an operation (perhaps because of changes to chain state between transaction creation and inclusion times), it may make sense to check this account's health immediately, before performing other operations. This will save gas by failing the transaction early.

### Forgiveness

If a controller wants to waive the liquidity check for an account it is controlling, it can "forgive" an account. This removes it from the set of accounts that will be checked at the end of batch. Controllers can only forgive accounts that they are the sole controller of.

Needless to say, this functionality should be used with care. It should only be necessary in certain advanced liquidation flows where an unhealthy account is impersonated but the seizure of funds is still not enough to bring the account to a sufficiently healthy level to pass the account status check.

When doing so, it is important that vaults verify that no *other* collaterals have unexpectedly been withdrawn during the seizure, in the event that a vault makes any external calls in its transfer/withdraw/etc method.



## Vault Status Checks

Some vaults may have constraints that should be enforced globally. For example, supply and/or borrow caps that restrict the maxium amount of assets that can be supplied or borrowed, as a risk minimisation.

It does not necessarily make sense to enforce these checks when checking account status. First of all, if many accounts are affected within a batch, checking these global constraints each time would be redundant.

Secondly, some types of checks require an initial snapshot of the vault state before any operations have been performed. In the case of a borrow cap, it could be that the borrow cap has been exceeded for some reason (perhaps due to a price movement, or the borrow cap itself was reduced). The vault would still want to permit repaying debts, even if the repay was insufficient to bring the total borrows below the borrow cap.

To implement this, vaults should expose an extenal `checkVaultStatus` function. The vault should evaluate application-specific logic to determine whether or not the vault is in an acceptable state, either returning `true` or failing by returning `false` (or throwing an exception).

Although the vaults themselves implement `checkVaultStatus`, there is no need for them to invoke this function directly. It will be called by the CVC when necessary. Instead, after performing any operation that could affect vault's status, a vault should invoke `requireVaultStatusCheck` on the CVC. 

Upon `requireVaultStatusCheck` call, the CVC will determine whether the current execution context is in a batch and if so, it will defer checking the status for this vault until the end of the execution context. Otherwise, the vault status check will be performed immediately.

In order to evaluate the vault status, `checkVaultStatus` may need access to a snapshot of the initial vault state. The recommended pattern as implemented in the reference vaults is as follows:

* Each action that requires a vault status check should first make an appropriate snapshot and store the data in transient storage
* The action should then call `requireVaultStatusCheck`
* `checkVaultStatus` should evaluate the vault status by unpacking the snapshot data stored in transient storage and compare it against the current state of the vault, and return `false` (or revert) if there is a violation.

As with the account status check, there is a subtle complication that vault implementations should consider if they use reentrancy guards (which is recommended). When a vault is invoked *without* vault status checks being deferred (ie, directly, not via the CVC), then when it calls `requireVaultStatusCheck` on the CVC, the CVC may immediately call back into the vault's `checkVaultStatus` function. A normal reentrancy guard would fail upon re-entering at this point. Because of this, the vault reference implementation relaxes the reentrancy modifier to allow `checkVaultStatus` call while invoking `requireVaultStatusCheck`.


## Execution

### Batches

At the time of this writing, public/private keypair Ethereum accounts (EOAs) cannot directly perform multiple operations within a single transaction, except by invoking a smart contract that will do so on their behalf. The CVC exposes a `batch` function that allows multiple operations to be executed together. This has several advantages for users:

* Atomicity: The user knows that either all of the operations in a batch will execute, or none of them will, so there is no risk of being left with partial or inconsistent positions.
* Gas savings: If contracts are invoked multiple times, then the cost of "cold" access can be amortised across all of the invocations.
* Status check deferrals: Sometimes it is more convenient or efficient to perform some operation that would leave an account/vault in an invalid state, but fix this state in a subsequent operation in a batch. For example, you may want to borrow and swap *before* you deposit your collateral. With batches, these checks can be performed once at the end of a batch (which can also itself be more gas efficient).

### Authorisation

Inside each batch item, an `onBehalfOfAccount` can be specified. The `batch` function will determine whether or not `msg.sender` is authorised to perform operations on this account:

* If they share the first 19 bytes, then `onBehalfOfAccount` is considered to be a *sub-account* of `msg.sender` and therefore `msg.sender` is authorised.
* If `onBehalfOfAccount` is `address(0)` then it is considered to be `msg.sender` and is therefore authorised (this is a calldata gas optimisation)
* If the `onBehalfOfAccount` has previously had `installAccountOperator` called to install `msg.sender` as an *operator* for this account, it is authorised.
* In all other cases, the the batch item is invalid, and the entire batch transaction will fail unless the batch item allows for failure.

#### Sub-Accounts

Sub-accounts allow users access to multiple (up to 256) virtual accounts that are entirely isolated from one another. Although multiple separate Ethereum addresses could be used, sub-accounts are often more efficient and convenient because their operations can be grouped together in a batch without setting approvals.

Since an account can only have one controller at a time (except for mid-transaction), sub-accounts are also the only way an Ethereum account can hold multiple borrows concurrently.

The CVC also maintains a look-up mapping `ownerLookup` so sub-accounts can be easily resolved to owner addresses, on or off chain. This mapping is populated when an address interacts with the CVC for the first time. In order to resolve a sub-account, call the `getAccountOwner` function with a sub-account address. It will either return the account's primary address, or revert with an error if the account has not yet interacted with the CVC.

#### Operators

Operators are a more flexible and powerful version of approvals. While in effect, the operator contract can act on behalf of the specified account. This includes interacting with vaults (ie, withdrawing/borrowing funds), enabling vaults as collateral, etc. Because of this, it is recommended that only trusted and audited contracts, or an EOA held by a trusted individual, be installed as an operator.

Operators have many use cases. For instance, a user might want to install a modifier such as stop-loss/take-profit/trailing-stop to a position in an account. To accomplish this, special operator contract that allows "keepers" to close out the user's position when certain conditions are met can be selected as an operator. Multiple operators can be installed per account.

An operator is similar to a controller, in that an account gives considerable permissions to a smart contract (that presumably has been well audited). However, the important difference is that an account owner can always revoke an operator's privileges at any time, however they can not do so with a controller. Instead, the controller must release its own privileges. Another difference is that controllers can not change the account's collateral or controller sets, whereas an operator can.

#### Permit

Instead of invoking the CVC directly, signed messages called `permit`s can also be provided to the CVC. Permits can be invoked by anyone, but they will execute on behalf of the signer of the permit message. They are useful for implementing "gasless" transactions.

Permits are EIP-712 typed data messages with the following fields:

* `signer`: The address to execute the operation on behalf of.
* `nonceNamespace` and `nonce`: Values used to prevent replaying permit messages, and for sequencing (see below)
* `deadline`: A timestamp after which the permit becomes invalid.
* `data`: Arbitrary calldata that will be used to invoke the CVC. Typically this contains an invocation of the `batch` method.

There are two types of signature methods supported by permits: ECDSA, which is used by EOAs, and [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271) which is used by smart contract wallets. In both cases, the `permit` method is invoked. If the signature is exactly 65 bytes long, `ecrecover` is invoked. If the recovered address does not match `signer`, or for signature lengths other than 65, then an ERC-1271 verification is attempted, by staticcalling `isValidSignature` on `signer`.

After verifying `deadline`, `signature`, and `nonce`, the `data` will be used to invoke the CVC. Although other methods can be invoked, the most general purpose method to call is `batch`. Inside a batch, each batch item can specify an `onBehalfOfAccount` address. This can be any sub-account of the owner, and a given batch can affect multiple sub-accounts, just as a regular non-permit invocation of `batch`. If the `signer` is an operator of another account, then this other account can also be specified -- this could be useful for gaslessly invoking a restricted "hot wallet" operator.

Internally, `permit` works by `call`ing `address(this)`, which has the effect of setting `msg.sender` to the CVC itself, indicating to the CVC that the actually authenticated user should be taken from the execution context. It is critical that a permit is the only way for this to happen, otherwise the authentication could be bypassed. Note that the CVC can be re-invoked via a batch, but this is done with *delegatecall*, leaving `msg.sender` unchanged.

##### Nonce Namespaces

Nonces in Ethereum transactions enforce that transactions cannot be included multiple times, and that they are included in the same sequence they were created (with no gaps).

`permit` messages contain two fields that can be used to enforce the same restrictions: `nonceNamespace` and `nonce`. Each account owner has a mapping that maps from `nonceNamespace` to `nonce`, where `nonce` is a `uint256`. In order for a permit message to be valid, the `nonce` value inside the specified `nonceNamespace` must be one less than the `nonce` field in the permit message.

The separation of `nonceNamespace` and `nonce` allows users to optionally relax the sequencing restrictions. There are several ways that an owner may choose to use the namespaces:

* Always set `nonceNamespace` to `0`, and sign sequentially increasing `nonce`s. These permit messages will function like Ethereum transactions, and must be mined in order, with no gaps.
* Derive the `nonceNamespace` deterministically from the message, perhaps by taking the message hash, and always set the `nonce` to `1`. These permit messages can be mined in any order, and some may never be mined.
* Some combination of the two approaches. For example, a user could have "regular" and "high priority" namespaces. Normal orders would be included in sequence, while high priority permits are allowed to bypass this queue.

Note that any time sequencing restrictions are relaxed, users must take into account that different orderings of their transactions can have different MEV potential, and they should prepare for their transactions executing in the least favourable order (for them).

Permit messages can be cancelled in two ways:

* Creating a new message with the same nonce and having it included before the unwanted message (as with Ethereum transactions).
* Invoking the `setNonce` method. This allows users to increase their nonce up to a specified value, potentially cancelling many outstanding permit messages in the process. Note that there is no danger of rendering an account non-functional: Even if a nonce is set to the max `uint256`, there are an effectively unlimited number of other namespaces available.



### call

The `call` function on the CVC allows users to invoke functions on vaults and other target smart contracts. Unless the `msg.sender` is the same as the `onBehalfOfAccount`, users *must* go through this function. This is because vaults themselves don't understand sub-accounts or operators, and only need to verify that they are being invoked by the CVC (see the Authentication By Vaults section).

`call` also allows users to invoke arbitrary contracts, with arbitrary calldata. These other contracts will see the CVC as `msg.sender`. For this reason, it is critical that the CVC itself never be given any special privileges, or hold any token or ETH balances (except for a few corner cases where it is temporarily safe, see the CVC Contract Privilege section).

Batches can be composed of calls to the CVC itself, and external `call` calls (when the `targetContract` is not the CVC). Calling the CVC is how users can enable collateral from within a batch, for example.

Batches will often be a mixture of external calls, some of which call vaults and some of which call other unrelated contracts. For example, a user might withdraw from one vault, then perform a swap on Uniswap, and then deposit into another vault.


### impersonate

The `impersonate` function can only be used in one specific case: When a controller vault wants to invoke a function on a collateral vault on behalf of the account under its control. The typical use-case for this is a liquidation. The controller vault would detect that an account entered violation due to a price movement, and seize some of collateral asset to repay the debt.

This is accomplished is by the controller vault calling `impersonate` and passing the collateral vault as the target contract and the violator as `onBehalfOfAccount`. The controller would construct a `withdraw` call using the its own address as the `receiver`. The collateral vault does not need to know that the funds are being withdrawn due to a liquidation.



### Execution Contexts

As mentioned above, when interacting with the CVC, it is often useful to defer certain checks until the end of the transaction. This allows a user to temporarily violate some of the constraints imposed by the vaults being interacted with, so long as the constraints are satisfied at the end of the transaction.

In order to implement this, the CVC maintains an *execution context* which holds two sets of addresses in regular or transient storage (if supported): `accountStatusChecks` and `vaultStatusChecks`. The execution context will also contain the `onBehalfOfAccount` that has currently been authenticated, so it can be queried for by a vault (see security considerations).

An execution context will exist for the duration of the batch, and is then discarded. Only one execution context can exist at a time. However, nesting batches *is* allowed (see below).

When the execution context is complete, the address sets are iterated over:

* For each address in `accountStatusChecks`, confirm that at most one controller is installed (its `accountControllers` set is of size 0 or 1). If a controller is installed, invoke `checkAccountStatus` on the controller for this account and ensure that the controller is satisfied.
* For each address in `vaultStatusChecks`, call `checkVaultStatus` on the vault address stored in the set and ensure that the vault is satisfied.

Additionally, the execution context contains some locks that protect critical regions from re-entrancy (see below).

#### Nested Execution Contexts

If a vault or other contract is invoked via the CVC, and that contract in turn re-invokes the CVC to call another vault/contract, then the execution context is considered nested. The execution context is however *not* treated as a stack. The sets of deferred account and vault status checks are added to, and only after unwinding the final execution context will they be validated.

Internally, the execution context stores a `batchDepth` value that increases each time a batch is started and decreases when it ends. Only once it decreases to the initial value of `0` do the deferred checks get performed. Nesting batches is useful because otherwise calling contracts from a batch that themselves want to defer checks would be more complicated, and these contracts would need two code-paths: one that defers and one that doesn't.

The previous value of `onBehalfOfAccount` is stored in a local "cache" variable and is subsequently restored after invoking the target contract. This ensures that contracts can rely on the `onBehalfOfAccount` at all times when `msg.sender` is the CVC. However, they can not necessarily rely on this value not changing when they invoke user-controllable callbacks (because they could created a nested context).

#### checksLock

The CVC invokes the `checkAccountStatus` and `checkVaultStatus` using call instead of staticcall so that controllers can checkpoint state during these operations. However, because of this there is a danger that the CVC could be re-entered during these operations, either directly by a controller, or indirectly by a contract it invokes.

Because of this, the CVC maintains a `checksLock` mutex that is acquired before unwinding the sets of accounts and vaults that need checking. This mutex is also checked during operations that alter these sets. If it did not do this, then information cached by the higher-level unwinding function (such as the sizes of the sets) could become inconsistent with the underlying storage, which could be used to bypass these critical checks.

#### impersonateLock

The typical use-case for impersonation is for a liability vault to seize collateral assets during a liquidation flow.

However, when interacting with complicated vaults that may invoke external contracts during a withdraw/transfer, a liability vault may want to ensure that no *other* collaterals are removed during the seizure.

In order to simplify the implementation of this check, the `impersonateLock` mutex is locked while invoking a collateral vault during the `impersonate` flow. While locked, no accounts' collateral or controller sets can be modified.

Additionally, during an impersonation, the CVC cannot be re-entered via `call`, `batch`, or `impersonate`.



### Simulations

The CVC also supports executing batches in a "simulation" mode. This is only intended to be invoked "off-chain", and is useful for user interfaces because the can show the user what the expected outcome will be of a sequence of operations.

Simulations work by actually performing the requested operations but then reverting, which (if called on-chain) reverts all the effects. Although simple in principle, there are a number of design elements involved:

* Intermediate read-only queries can be inserted into a batch to gather simulated data useful for display
* The results are available even if status checks would cause a failure, for example so that a user can see exactly what is causing the failure
* Although internally simulations work by reverting, the recommended interface returns it as regular return data, which causes fewer compatibility problems (sometimes error data is mangled or dropped). This is the reason for `batchRevert`: You can't do a "try/catch" without an external call, so this must be an external function, although we recommend using the `batchSimulation` entry point instead.
* Simulations don't have the side-effect of making regular batches create large return-data (which would be gas inefficient)



## Transient Storage

In order to maintain the execution context, access to the same variables must occur from different invocations of the CVC. This means that they must be held in storage, and not memory. Unfortunately, storage is expensive compared to memory. Luckily, the EVM protocol may soon specify a new type of memory lifetime: transient storage that is accessible to multiple invocations, but is inexpensive to access.

In order to take advantage of transient storage, the contracts have been structured to keep all the variables that should be stored in transient storage in a separate base class contract `TransientStorage`. By optionally overriding this at compile-time, both old and new networks can be supported.



## Security Considerations

### Authentication by Vaults

In order to support sub-accounts, operators, and impersonating (ie, liquidations), vaults can be invoked via the CVC's `call`, `batch`, or `impersonate` functions, which will then execute the desired operations on the vault. However, in this case the vault will see the CVC as the `msg.sender`.

When a vault detects that `msg.sender` is the CVC, it should call back into the CVC to retrieve the current execution context using `getExecutionContext`. This will tell the vault two things:

* The `onBehalfOfAccount` which indicates the account that has been authenticated by the CVC. The vault should consider this the "true" value of `msg.sender` for authorisation purposes.
* The `controllerEnabled` which indicates whether or not the `controllerToCheck` vault address, with which the function has been invoked, is currently enabled as a controller for the current `onBehalfOfAccount` account. This information is only considered valid when `getExecutionContext` is invoked with `controllerToCheck` set to non-zero address. When `controllerToCheck` is set to zero address (which optimizes gas consumption), the value returned is always `false`. This information is needed if the vault is performing an operation (such as a borrow) that requires it to be the controller for an account.

### CVC Contract Privileges

Because the CVC contract can be made to invoke any arbitrary target contract with any arbitrary calldata, it should never be given any privileges, or hold any ETH or tokens.

The only exception to this is mid-transaction inside of a batch. If one batch item temporarily moves ETH or tokens into the CVC, but a subsequent batch item moves it out, then because batches execute atomically, it is safe. However, generally moving tokens to the CVC is not necessary, because tokens can usually be moved immediately to their final destination with `transferFrom` etc.

One exception to this is wrapping ETH into WETH. The deposit method will always credit the caller with the WETH tokens. In this case, the user must transfer the WETH in a subsequent batch item.

One area where the untrustable CVC address may cause problems is tokens that implement hooks/callbacks, such as ERC-777 tokens. In this case, somebody could install a hook for the CVC as a recipient, and cause inbound transfers to fail, or possibly even be redirected. Although the CVC doesn't attempt to comprehensively solve this, specifically for ERC-777 tokens and related systems, the ERC-1820 registry address is blocked and can not be invoked via `call` or batches.

### Read-only Re-entrancy

The non-transient storage maintained by the CVC *can* be read while checks are deferred. In particular, this includes the lists of collaterals and controllers registered for a given account.

This should not result in "read-only re-entrancy" problems, because each individual operation will leave these lists in a consistent state. In particular, for a controller to be released, that controller itself must invoke the release, which typically means the debt has been repaid.

If an external contract attempted to read the collateral or controller states of an account in order to enforce some policy of its own, then it is possible that a user could defer liquidity in a batch, repay the loan, invoke the external contract, and then re-take the loan. In this case the external contract would see the controller as being released. However, this same action could be done outside of a deferal by simply taking a flash loan from an external system, rather than using the batch deferal.
