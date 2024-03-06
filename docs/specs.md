# Ethereum Vault Connector and Vault Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## Definitions

- Ethereum Vault Connector (EVC): A smart contract that mediates between Vaults in order to enable their lending and borrowing functionality.
- Vault: A smart contract that accepts deposits of a single asset and issues shares in return, it MAY support borrowing functionality. It SHOULD implement the logic and interface necessary for interaction with other Vaults via the EVC. It MAY be, ERC-4626 compliant.
- Account: Every Ethereum address has 256 accounts in the EVC (one private key to rule them all). Each account has an account ID from 0-255. In order to compute the account addresses, the Account ID is treated as a uint and XORed (exclusive ORed) with the Ethereum address. Effectively, a group of 256 Accounts belonging to the same owner share the first 19 bytes of their address and differ only in the last byte.
- Account Owner: An EOA or a smart contract Ethereum address, one of the 256 Accounts with Account ID 0, that has ownership over the whole group of Accounts.
- Address Prefix: The first 19 bytes of the Ethereum address. Account Owner has a common Address Prefix with any of the Accounts that belong to them.
- Account Operator: An EOA or smart contract Ethereum address that has been granted permission to operate on behalf of the Account. The permission can only be granted by the Account Owner.
- Collateral Vault: A Vault which deposits are accepted as collateral for borrowing in other Vaults. An Account can enable multiple collaterals. Enabled collateral can be seized by the Controller Vault in case of liquidation.
- Controller Vault: A Vault that may be enabled by a user in order to be able to borrow from it. Enabling Controller submits the specified Account to the rules encoded in the Controller Vault's code. All the funds in all the enabled Collateral Vaults are indirectly under the control of the enabled Controller Vault; hence, the Accounts MUST only enable trusted, audited Controllers. If the Controller is malicious or incorrectly coded, it may result in the loss of the user's funds or even render the account unusable. Whenever a user wants to perform an action such as removing collateral, the Controller Vault is consulted in order to determine whether the action is allowed or whether it should be blocked since it would make the Account insolvent. An Account can have only one Controller Vault enabled at a time unless it's a transient state during checks deferral.
- Nonce Namespace: A value used in conjunction with Nonce to prevent replaying Permit messages and for sequencing. Each Nonce Namespace provides a uint256 Nonce that has to be used sequentially. There's no requirement to use all the Nonces for a given Nonce Namespace before moving to the next one, which allows using Permit messages in a non-sequential manner.
- Nonce: A value used to prevent replaying Permit messages and for sequencing. It is associated with a specific Nonce Namespace and an Address Prefix. The Nonce must be used sequentially within its Nonce Namespace. To invalidate signed Permit messages, set the Nonce for a given Nonce Namespace accordingly. To invalidate all the Permit messages for a given Nonce Namespace, set the Nonce to type(uint).max.
- Permit: A functionality based on the EIP-712 typed data message allowing arbitrary signed calldata execution on the EVC on behalf of the signer (Account Owner or Account Operator) of the message. It is useful for implementing "gasless" transactions.
- Call: A functionality allowing to execute arbitrary calldata on an arbitrary contract with Account and Vault Status Checks deferred. In case the target contract is the EVC, delegatecall is performed to preserve the msg.sender. If the target contract is msg.sender, the caller MAY specify any Account address to be set in the Execution Context. In case the target contract is not msg.sender, only the Account Owner or Account Operator are allowed to execute arbitrary calldata on behalf of the specified Account.
- Batch: Like Call, but allows a list of operations that are executed atomically one by one with Account and Vault Status Checks deferred.
- ControlCollateral: A functionality allowing an enabled Controller Vault to execute an arbitrary calldata on any of the enabled Collateral Vaults on behalf of the specified Account while Account and Vault Status Checks are deferred. The Controller Vault must be the only enabled Controller Vault for the Account in order to be able to control collateral. This functionality is useful for liquidation flows.
- Simulation: An entry point into the EVC that allows for simulating the execution of a batch without modifying the state. It is useful for inspecting the outcome of a batch before executing it.
- Account Status Check: A functionality implemented by Vaults to enforce Account solvency. Vaults MUST expose a special function that will receive an Account address and this Account's list of enabled Collateral Vaults in order to determine the Account's liquidity status. Account status is checked immediately or is deferred until the end of the outermost Checks-deferrable Call. Account Status Check deferral allows for a transient violation of the Account solvency.
- Vault Status Check: A functionality implemented by Vaults to enforce Vault constraints (i.e. supply/borrow caps). Vaults MAY expose a special function that implements necessary checks in order to determine acceptable state of the Vault. Vault status is checked immediately or is deferred until the end of the outermost Checks-deferrable Call. Vault Status Check deferral allows for a transient violation of the Vault constraints.
- Checks-deferrable Call: A functionality that defers the Account and Vault Status Checks, namely: Call, Batch or ControlCollateral call. Checks-deferrable Calls can be nested.
- Checks Deferral: A functionality allowing to defer Account and Vault Status Checks until the end of the outermost Checks-deferrable Call. This allows for a transient violation of the Account solvency or Vault constraints.
- Lockdown Mode: A security feature of the EVC that can be activated by the Account Owner. Once activated, it applies to all the Accounts owned by the Account Owner simultaneously, significantly reducing the functionality of the EVC for those Accounts. This mode is particularly useful in emergency situations, such as when a malicious operator has been added or a harmful permit message has been signed, to safeguard the owner's assets.
- Execution Context: A data structure maintained by the EVC that holds information about the current execution state. It tracks the currently authenticated Account address on behalf of which the current operation is being performed, a flag indicating whether the Checks are deferred, a flag indicating whether the Account/Vault Status Checks are in progress, a flag indicating whether the ControlCollateral is in progress, a flag indicating whether an Account Operator is currently operating on behalf of the Account and a flag indicating whether the Simulation is in progress.


## Ethereum Vault Connector Specification

1. An Owner of the group of 256 accounts MUST be recorded only once upon the first interaction of any of its Accounts with the EVC.
1. Only an Account Owner MUST be allowed to authorize an Account Operator to operate on behalf of the Account.
1. An Account MAY have multiple Account Operators.
1. Account Operator address MUST NOT belong to the Account Owner of the Account for which the Operator being is authorized.
1. Account Operator MUST be allowed to deauthorize itself for the Account if it is authorized to operate on behalf of it.
1. Only an Account Owner MUST be allowed to modify the Nonce for its Address Prefix and Nonce Namespace.
1. New Nonce MUST NOT be lower than or equal to the currently stored.
1. Each Account MUST have at most 20 Collateral Vaults enabled at a time.
1. Each Account MUST have at most one Controller Vault enabled at a time unless it's a transient state during a Checks-deferrable Call.
1. Only an Account Owner or the Account Operator MUST be allowed to enable and disable Collateral Vaults for the Account.
1. Only an Account Owner or the Account Operator MUST be allowed to reorder enabled Collateral Vaults for the Account.
1. Only an Account Owner or the Account Operator MUST be allowed to enable Controller Vaults for the Account.
1. Only an enabled Controller Vault for the Account MUST be allowed to disable itself for that Account.
1. The Controller Vault MUST NOT be allowed to use Permit in order to disable itself for an Account.
1. EVC MUST support signed Permit messages that allow anyone to execute arbitrary calldata on the EVC on behalf of the Account Owner or Account Operator who signed the message.
1. Signed Permit message MUST conform to the EIP-712 standard rules.
1. The type of the EIP-712 data structure MUST be encoded as follows: `Permit(address signer,uint256 nonceNamespace,uint256 nonce,uint256 deadline,uint256 value,bytes data)`.
1. For the signature to be considered valid, all of the below MUST be true:
- the `signer` address corresponds to the valid signer address obtained using standard `ecrecover` precompile or using ERC-1271 defined rules for standard signature verification methods for contracts
- `nonce` is equal to the current on-chain Nonce value for `signer`-corresponding Address Prefix and `nonceNamespace`
- `deadline` value is not greater than `block.timestamp` at the block of signature verification
- `value` does not exceed the value balance of the EVC contract at the time of signature verification, or is equal to `type(uint256).max`
- `data` field is not empty
1. Upon successful verification of the signature, EVC MUST increase the Nonce value corresponding to the Nonce Namespace and signer.
1. The authorization rules of the Permit message calldata execution MUST be as if the calldata were executed on the EVC directly.
1. EVC MUST support the following Checks-deferrable Call functions: Call, Batch and ControlCollateral that are re-entrant and allow to execute calldata on an external target contract addresses or the EVC.
1. Each Checks-deferrable Call function MUST specify an Account. The functions MUST determine whether or not `msg.sender` is authorized to perform operations on that Account. 
1. In Call and Batch, if the target is the EVC, the account specified MUST be zero for the sake of consistency. In that case, the EVC MUST be `delegatecall`ed to preserve the `msg.sender` and, depending on a function, a function-specific authentication is performed.
1. In Call and Batch, if the target is not `msg.sender`, only the Owner or an Operator of the specified Account MUST be allowed to perform Call and individual Batch operations on behalf of the Account.
1. In Call and Batch, if the target is `msg.sender`, the caller MAY specify any Account address to be set in the Execution Context's on behalf of Account address. In that case, the authentication is not performed.
1. In ControlCollateral, only the enabled Controller of the specified Account MUST be allowed to perform the operation on one of the enabled Collaterals on behalf of the Account. Neither the Controller nor Collateral Vault can be the EVC.
1. The Controller Vault MUST NOT be allowed to use Permit in order to use ControlCollateral.
1. EVC MUST maintain the Execution Context and make it publicly observable.
1. Execution Context MUST keep track of the Account on behalf of which the current low-level calldata call is being performed.
1. Execution Context MUST keep track of whether the Checks are deferred with a boolean flag. The flag MUST be set when a Checks-deferrable Call starts and MUST be cleared at the end of it, but only when the flag was `false` before the call.
1. Execution Context MUST keep track of whether the Account and Vault Status Checks are in progress.
1. Execution Context MUST keep track of whether the ControlCollateral is in progress.
1. Execution Context MUST keep track of whether an Account Operator was authenticated to perform the current low-level calldata call on behalf of the Account.
1. Execution Context MUST keep track of whether the Simulation is in progress.
1. EVC MUST allow to require Account and Vault Status Checks which will be performed immediately or deferred, depending on the Execution Context.
1. EVC MUST allow to defer required Account and Vault Status Checks performance until the flag indicating checks deferred is cleared. That SHOULD allow for a transient violation of the Account solvency or Vault constraints.
1. If the execution is not within a Checks-deferrable Call, required Account and Vault Status Checks MUST be performed immediately.
1. For the Account Status Check to be performed, there MUST be only one Controller enabled for an Account at the time of the Check.
1. If there is no Controller enabled for an Account at the time of the Check, the Account Status MUST always be considered valid. It includes disabling the only enabled Controller before the Checks.
1. If there is more than one Controller enabled for an Account at the time of the Check, the Account Status MUST always be considered invalid.
1. Both Account- and Vault-Status-Checks-related storage sets MUST return to their default state when the flag indicating checks deferred is cleared and the checks are performed.
1. EVC MUST allow for Account Status Checks to be deferred for at most 20 Accounts at a time.
1. EVC MUST allow for Vault Status Checks to be deferred for at most 20 Vaults at a time.
1. Execution Context MUST return to its default state when the flag indicating checks deferred is cleared.
1. Execution Context's Account on behalf of which the current low-level call is being performed MUST be storing address(0) when Account and Vault Status Checks are in progress.
1. If there's only one enabled Controller Vault for an Account, only that Controller MUST be allowed to forgive the Account Status Check if it's deferred.
1. EVC MUST allow a Vault to forgive the Vault Status Check for itself if it's deferred.
1. Forgiven Account and Vault Status Checks will not be performed when the flag indicating checks deferred is cleared, unless they are required again after the forgiveness.
1. Only the Checks-Deferrable Calls MUST allow to re-enter the EVC.
1. Simulation-related functions MUST NOT modify the state.

NOTE: In order to borrow, a user MUST enable a Controller. From then on, whenever the user wants to perform an action that may affect their solvency, the Controller MUST be consulted (the Account Status Check must be performed) in order to determine whether the action is allowed or whether it should be blocked since it would make the account insolvent. The Account Status Check MUST be required on any operation that may affect the Account's solvency. The EVC determines whether the check should be deferred or performed immediately.

NOTE: Enabling a Controller submits the account to the rules encoded in the Controller contract's code. All the funds in all enabled Collateral Vaults are now indirectly under the control of the Controller Vault.

NOTE: Only the Controller can disable itself for the Account. This should typically happen upon an Account repaying its debt in full.

NOTE: The protocol deliberately doesn't enforce specific properties about the assets being used as collateral or liabilities. EVC users can therefore create vaults backed by irregular asset classes, such as NFTs, RWAs, uncollateralised IOUs, or synthetics.

NOTE: While it might be tempting for the Controller to allow a broad range of Collateral vaults to encourage borrowing, the Controller vault creators MUST exercise caution when deciding which vaults to accept as collateral. A malicious or incorrectly coded vault could, among other things, misrepresent the amount of assets it holds, reject liquidations when a user is in violation, or fail to require Account Status Checks when necessary. Therefore, vaults SHOULD limit allowed collaterals to a set of audited addresses known to be reliable or verify the addresses in a registry or factory contract to ensure they were created by trustworthy, audited contracts.

NOTE: Accounts are fully isolated and can be treated as independent positions. Failing Account Status Check (ruled by enabled Controller Vault) may affect the ability to interact with the Account, including operations on the Vaults that are not enabled as Collaterals. In order to make the Account fully functional again, one MUST satisfy the Controller Vault conditions.

NOTE: Because the EVC contract can be made to invoke any arbitrary target contract with any arbitrary calldata, it SHOULD never be given any privileges, or hold any value or tokens.
