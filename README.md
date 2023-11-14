# Ethereum Vault Connector

The Ethereum Vault Connector (EVC) is an attempt to distill the core functionality required for a lending market into a foundational layer that can be used as a base building block for many diverse protocols. The EVC is primarily a mediator between Vaults, which are contracts that implement the ERC-4626 interface and contain a small amount of additional logic for interfacing with other vaults.

For more information refer to the [WHITEPAPER](docs/whitepaper.md) and the [SPECS](docs/specs.md).

---

## Contracts

```
.
├── interfaces
│   ├── IERC1271.sol
│   ├── IEthereumVaultConnector.sol
│   └── IVault.sol
├── Errors.sol
├── EthereumVaultConnector.sol
├── Events.sol
├── ExecutionContext.sol
├── Set.sol
└── TransientStorage.sol
```

## Install

To install Ethereum Vault Connector in a [**Foundry**](https://github.com/foundry-rs/foundry) project:

```sh
forge install euler-xyz/euler-evc
```

## Usage

The Ethereum Vault Connector comes with a comprehensive set of tests written in Solidity, which can be executed using Foundry.

For a detailed understanding of the Ethereum Vault Connector and considerations for its integration, please refer to the [WHITEPAPER](docs/whitepaper.md) and the [SPECS](docs/specs.md). You can find examples of vaults utilizing the Ethereum Vault Connector in the [EVC Playground](https://github.com/euler-xyz/euler-evc-playground/tree/master/src) repository. However, these example vaults are not meant for production use as they have not been audited and are intended solely for testing and experimentation purposes.

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
git clone https://github.com/euler-xyz/euler-evc.git && cd euler-evc && yarn
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
scribble test/evc/EthereumVaultConnectorScribble.sol --output-mode files --arm && forge test
```

To remove instrumentation:

```sh
scribble test/evc/EthereumVaultConnectorScribble.sol --disarm
```

### in `coverage` mode

```sh
forge coverage
```

## Safety

This software is **experimental** and is provided "as is" and "as available".

**No warranties are provided** and **no liability will be accepted for any loss** incurred through the use of this codebase.

Always include thorough tests when using the Ethereum Vault Connector to ensure it interacts correctly with your code.

The Ethereum Vault Connector **has not yet undergone an audit** and should not be used in production.

## Known limitations

Refer to the [WHITEPAPER](docs/whitepaper.md#security-considerations) for a list of known limitations and security considerations.

## Contributing

The code is currently in an experimental phase leading up to the first audit. Feedback or ideas for improving the Ethereum Vault Connector are appreciated. Contributions are welcome from anyone interested in conducting security research, writing more tests including formal verification, improving readability and documentation, optimizing, simplifying, or developing integrations.

## License

Licensed under the [GPL-2.0-or-later](/LICENSE) license.
