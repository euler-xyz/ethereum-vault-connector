# Using Certora
## Setup
1. [Install Certora](https://docs.certora.com/en/latest/docs/user-guide/getting-started/install.html)
1. Add API Key to environment
```
❯ export CERTORAKEY=...
```
3. Verify installed version
```
❯ certoraRun --version
certora-cli 4.10.1
```
## Folder structure
* `certora/conf`: Certora prover configurations per contract
* `certora/harness`: Helper contracts for verifications
* `certora/scripts`: Shell scripts for running the Certora prover
* `certora/specs`: Specification files with rules

## Running Certora
### Run all
```
❯ sh certora/scripts/verify_all.sh
```
### Run specific contract
```
❯ sh certora/scripts/verify_set.sh
```
### Run specific rule
```
❯ sh certora/scripts/verify_set.sh noOOBWrite
```
### 