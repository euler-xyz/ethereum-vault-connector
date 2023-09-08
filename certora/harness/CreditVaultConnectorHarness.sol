// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../../src/CreditVaultConnector.sol";
import "../../src/interfaces/ICreditVaultConnector.sol";
import "../../src/Set.sol";

contract CreditVaultConnectorHarness is CreditVaultConnector {
    function numAccountCollaterals(address account) external view returns (uint8) {
        return accountCollaterals[account].numElements;
    }

    function numAccountControllers(address account) external view returns (uint8) {
        return accountControllers[account].numElements;
    }

    function isAccountOperator(address account, address operator) external view returns (bool) {
        return accountOperators[account][operator];
    }

    function getOwnerLookup(uint152 prefix) external view returns (address owner) {
        return ownerLookup[prefix];
    }

    function getExecutionContext() external view returns (ICVC.ExecutionContext memory) {
        return executionContext;
    }

    function getExecutionContextChecksLock() external view returns (bool) {
        return executionContext.checksLock;
    }

    function getExecutionContextImpersonateLock() external view returns (bool) {
        return executionContext.impersonateLock;
    }

    function getExecutionContextBatchDepth() external view returns (uint8) {
        return executionContext.batchDepth;
    }

    function getExecutionContextOnBehalfOfAccount() external view returns (address) {
        return executionContext.onBehalfOfAccount;
    }

    function getExecutionContextReserved() external view returns (uint8) {
        return executionContext.reserved;
    }

    function getAccountStatusChecks() external view returns (SetStorage memory) {
        return accountStatusChecks;
    }

    function getAccountStatusChecksSize() external view returns (uint8) {
        return accountStatusChecks.numElements;
    }

    function getVaultStatusChecks() external view returns (SetStorage memory) {
        return vaultStatusChecks;
    }

    function getVaultStatusChecksSize() external view returns (uint8) {
        return vaultStatusChecks.numElements;
    }
}