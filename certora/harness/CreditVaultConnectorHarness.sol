// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../../src/CreditVaultConnector.sol";

contract CreditVaultConnectorHarness is CreditVaultConnector {
    /// @dev Certora prover erroneously thinks `address(this).delegatecall(item.data)` can arbitrarily mutate storage.
    /// We replace the delegatecall with a call table
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
                // No fallback / receive function
                require(item.data.length >= 4);

                bytes4 selector = item.data[:4];

                if (selector == this.setAccountOperator.selector) {
                    (success, result) = setAccountOperator{value: msg.value}(item.data[5:]);
                } else if (selector == this.enableCollateral.selector) {
                    (success, result) = enableCollateral{value: msg.value}(item.data[5:]);
                } else {
                    // TODO
                    // No fallback function
                    revert("");
                }
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
        return accountOperators[account][operator];
    }

    function getOwnerLookup(uint152 prefix) external view returns (address owner) {
        return ownerLookup[prefix];
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

    function getAccountStatusChecksSize() external view returns (uint8) {
        return accountStatusChecks.numElements;
    }

    function getVaultStatusChecksSize() external view returns (uint8) {
        return vaultStatusChecks.numElements;
    }
}