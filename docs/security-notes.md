# Security Notes

Notes for contracts that integrate with the Ethereum Vault Connector. The deployed EVC is immutable, so these notes describe behaviour that will not change on existing deployments.

## Execution context during ERC-1271 signature validation

`permit` verifies a smart contract signature by staticcalling `isValidSignature` on the `signer`, and it does so before it sets the permit's own execution context. While `isValidSignature` runs:

- `msg.sender` is the EVC.
- The execution context still holds the `onBehalfOfAccount` of any enclosing checks-deferrable call.
- That account need not belong to the `signer`. When the enclosing `call` or `batch` item targets its own caller, the caller set the account without authentication (requirement CER-23 in the [specs](./specs.md)).

A contract that answers `isValidSignature`, and any code it reaches, must therefore not authenticate through the EVC. This rules out:

- treating `msg.sender == evc` together with `getCurrentOnBehalfOfAccount` or `getRawExecutionContext` as an authenticated caller;
- `EVCUtil` helpers built on that pattern, such as `_msgSender()`, `_msgSenderForBorrow()`, `onlyEVCAccount` and `onlyEVCAccountOwner`.

Validate the signature against state the `signer` controls, such as an owner's ECDSA key or signatures it has approved on-chain.

The guarantee that `onBehalfOfAccount` can be trusted when `msg.sender` is the EVC (see [Authentication by Vaults](./whitepaper.md#authentication-by-vaults)) does not cover this call.
