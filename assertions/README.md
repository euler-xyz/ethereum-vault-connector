# Assertions

This directory contains Phylax Credible Layer assertions for the Ethereum Vault Connector by Euler.

## Installation

### Clone with Submodules

If cloning the repository for the first time:

```bash
git clone --recursive <repo-url>
```

### Install Dependencies

Install the required dependencies:

```bash
forge install phylaxsystems/credible-std
forge install foundry-rs/forge-std
forge install OpenZeppelin/openzeppelin-contracts
```

### Update Submodules

If the repository was already cloned or you need to update submodules:

```bash
git submodule update --init --recursive
```

## Running Tests

To run the assertion tests, use the `pcl test` command:

```bash
# Run all assertion tests
pcl test

# Run with assertions profile (recommended)
FOUNDRY_PROFILE=assertions pcl test

# Run specific test file
pcl test assertions/test/VaultStatusCheck.t.sol
pcl test assertions/test/VaultSharePriceAssertion.t.sol

# Run with verbose output for debugging
pcl test -vvv
```

## Building Assertions

To build the assertions:

```bash
pcl build
```
