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

The Credit Vault Connector comes with a comprehensive set of tests written in Solidity, which can be executed using Foundry.

For a detailed understanding of the Credit Vault Connector and considerations for its integration, please refer to the [WHITEPAPER](docs/whitepaper.md) and the [SPECS](docs/specs.md). You can find examples of vaults utilizing the Credit Vault Connector in the [CVC Playground](https://github.com/euler-xyz/euler-cvc-playground/tree/master/src) repository. However, these example vaults are not meant for production use as they have not been audited and are intended solely for testing and experimentation purposes.

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

This software is **experimental** and is provided "as is" and "as available".

**No warranties are provided** and **no liability will be accepted for any loss** incurred through the use of this codebase.

Always include thorough tests when using the Credit Vault Connector to ensure it interacts correctly with your code.

The Credit Vault Connector **has not yet undergone an audit** and should not be used in production.

## Known limitations

Refer to the [WHITEPAPER](docs/whitepaper.md#security-considerations) for a list of known limitations and security considerations.

## Contributing

The code is currently in an experimental phase leading up to the first audit. Feedback or ideas for improving the Credit Vault Connector are appreciated. Contributions are welcome from anyone interested in conducting security research, writing more tests including formal verification, improving readability and documentation, optimizing, simplifying, or developing integrations.

## License

Licensed under the [GPL-2.0-or-later](/LICENSE) license.
