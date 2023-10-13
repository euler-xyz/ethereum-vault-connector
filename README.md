# Credit Vault Connector

The Credit Vault Connector (CVC) is an attempt to distill the core functionality required for a lending market into a foundational layer that can be used as a base building block for many diverse protocols. The CVC is primarily a mediator between Credit Vaults, which are contracts that implement the ERC-4626 interface and contain a small amount of additional logic for interfacing with other vaults.

For more information refer to the [WHITEPAPER](docs/whitepaper.md) and the [SPECS](docs/specs.md).

---

## Contracts

```
.
├── interfaces
│   ├── ICreditVault.sol
│   ├── ICreditVaultConnector.sol
│   └── IERC1271.sol
├── CreditVaultConnector.sol
├── ExecutionContext.sol
├── Set.sol
└── TransientStorage.sol
```

## Install

To install Credit Vault Connector in a [**Foundry**](https://github.com/foundry-rs/foundry) project:

```sh
forge install euler-xyz/euler-cvc
```

## Usage

Credit Vault Connector includes a suite of tests written in Solidity with Foundry.

Please refer to the [WHITEPAPER](docs/whitepaper.md) and the [SPECS](docs/specs.md) for an in-depth explanation of the Credit Vault Connector and integration considerations. Example vaults using the Credit Vault Connector can be found in the [CVC Playground](https://github.com/euler-xyz/euler-cvc-playground/tree/master/src) repo. Do not use the example vaults in production under any circumstances as they are not audited and are only meant to be used for testing and experimentation.

To install Foundry:

```sh
curl -L https://foundry.paradigm.xyz | bash
```

This will download foundryup. To start Foundry, run:

```sh
foundryup
```

To clone the repo and install dependencies:

```sh
git clone https://github.com/euler-xyz/euler-cvc.git && cd euler-cvc && yarn
```

## Testing

### in `default` mode

To run the tests in a `default` mode:

```sh
forge test
```

### with `scribble` annotations

To run the tests using `scribble` annotations first install [scribble](https://docs.scribble.codes/):

```sh
npm install -g eth-scribble
```

To instrument the contracts and run the tests:

```sh
scribble test/cvc/CreditVaultConnectorScribble.sol --output-mode files --arm && forge test
```

To remove instrumentation:

```sh
scribble test/cvc/CreditVaultConnectorScribble.sol --disarm
```

### in `coverage` mode

```sh
forge coverage
```

## Safety

This is **experimental software** and is provided on an "as is" and "as available" basis.

**No warranties are given** and **nobody will be liable for any loss** incurred through any use of this codebase.

Please always include your own thorough tests when using Credit Vault Connector to make sure it works correctly with your code.

At this point in time Credit Vault Connector **has not yet been audited** and must not be used in production.

## Known limitations

Please refer to the [WHITEPAPER](docs/whitepaper.md#security-considerations) for a list of known limitations and security considerations.

## Contributing

The code is currently in an experimental phase leading up to the first audit. Any feedback or ideas how Credit Vault Connector can be improved will be appreciated. Contributions are welcome by anyone interested in carrying out security research, writing more tests including formal verification, improving readability and documenation, optimizing, simplifying or developing integrations.

## License

Licensed under the [GPL-2.0-or-later](/LICENSE) license.
