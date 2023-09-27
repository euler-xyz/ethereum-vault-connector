// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../../src/CreditVaultConnector.sol";
import "../../src/ExecutionContext.sol";

contract CreditVaultConnectorHarness is CreditVaultConnector {
    using ExecutionContext for EC;

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
                // todo implement call table for public methods, implement workaround for external methods
                revert("");
            } else {
                address onBehalfOfAccount = item.onBehalfOfAccount == address(0)
                    ? msg.sender
                    : item.onBehalfOfAccount;

                (success, result) = callInternal(
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

    function numAccountCollaterals(address account) external view returns (uint8) {
        return accountCollaterals[account].numElements;
    }

    function numAccountControllers(address account) external view returns (uint8) {
        return accountControllers[account].numElements;
    }

    function isAccountOperator(address account, address operator) external view returns (bool) {
        return operatorLookup[account][operator].authExpiryTimestamp < block.timestamp ;
    }

    function getOwnerLookup(uint152 prefix) external view returns (address owner) {
        return ownerLookup[prefix].owner;
    }

    function getExecutionContextIgnoringStamp() external view returns (uint256) {
        return EC.unwrap(executionContext) & ~ExecutionContext.STAMP_MASK;
    }

    function getExecutionContextChecksLock() external view returns (bool) {
        return executionContext.areChecksInProgress();
    }

    function getExecutionContextImpersonateLock() external view returns (bool) {
        return executionContext.isImpersonationInProgress();
    }

    function getExecutionContextBatchDepth() external view returns (uint8) {
        return uint8(EC.unwrap(executionContext) & ExecutionContext.BATCH_DEPTH_MASK);
    }

    function getExecutionContextBatchDepthIsInit() external view returns (bool) {
        return !executionContext.isInBatch();
    }

    function getExecutionContextOnBehalfOfAccount() external view returns (address) {
        return executionContext.getOnBehalfOfAccount();
    }

    function getAccountStatusChecksSize() external view returns (uint8) {
        return accountStatusChecks.numElements;
    }

    function getVaultStatusChecksSize() external view returns (uint8) {
        return vaultStatusChecks.numElements;
    }
}