// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../../src/CreditVaultConnector.sol";

contract CreditVaultConnectorHarness is CreditVaultConnector {
    /// @dev Certora prover erroneously thinks `address(this).delegatecall(item.data)` can arbitrarily mutate storage.
    function batchInternal(
        BatchItem[] calldata items,
        bool returnResult
    ) internal override returns (BatchItemResult[] memory batchItemsResult) {
        uint length = items.length;

        if (returnResult) {
            batchItemsResult = new BatchItemResult[](length);
        }

        for (uint i; i < length; ) {
            BatchItem calldata item = items[i];
            address targetContract = item.targetContract;
            bool success;
            bytes memory result;

            if (targetContract == address(this)) {
                // Changed
                success = harness_delegatecall();
            } else {
                address onBehalfOfAccount = item.onBehalfOfAccount == address(0)
                    ? msg.sender
                    : item.onBehalfOfAccount;

                // Changed
                (success, result) = harness_callInternal(
                    targetContract,
                    onBehalfOfAccount,
                    item.value,
                    item.data
                );
            }

            if (returnResult) {
                batchItemsResult[i].success = success;
                batchItemsResult[i].result = result;
            } else if (!success) {
                revertBytes(result);
            }

            unchecked {
                ++i;
            }
        }
    }

    /// @dev Summarized in CVL
    function harness_delegatecall() public returns (bool success) {}

    /// @dev Summarized in CVL
    function harness_callInternal(
        address targetContract,
        address onBehalfOfAccount,
        uint value,
        bytes calldata data
    ) public returns (bool success, bytes memory result) {
        return callInternal(targetContract, onBehalfOfAccount, value, data);
    }

    function numAccountCollaterals(address account) external view returns (uint8) {
        return accountCollaterals[account].numElements;
    }

    function numAccountControllers(address account) external view returns (uint8) {
        return accountControllers[account].numElements;
    }

    function isAccountOperator(address account, address operator) external view returns (bool) {
        return operatorLookup[account][operator].authExpiryTimestamp >= block.timestamp;
    }

    function getOwnerLookup(uint152 prefix) external view returns (address owner) {
        return ownerLookup[prefix].owner;
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

    function getExecutionContextStamp() external view returns (uint72) {
        return executionContext.stamp;
    }

    function getAccountStatusChecksSize() external view returns (uint8) {
        return accountStatusChecks.numElements;
    }

    function getVaultStatusChecksSize() external view returns (uint8) {
        return vaultStatusChecks.numElements;
    }
}