// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../../src/CreditVaultConnector.sol";
import "../../src/ExecutionContext.sol";
import "../../src/Set.sol";
import "./CreditVaultStub.sol";

contract CreditVaultConnectorHarness is CreditVaultConnector {
    using Set for SetStorage;
    using ExecutionContext for EC;

    bool public ret_isValidERC1271Signature;
    bool public callHandler_wasHit = false;
    bool public callHandler_doRevert;
    bool public callHandler_doCheckMsgSender;
    address public callHandler_checkedMsgSender;

    CreditVaultStub creditVaultStub;
    

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
                (success, result) = address(this).delegatecall(item.data);
            } else {
                (success, result) = callInternal(
                    targetContract,
                    item.onBehalfOfAccount,
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

    /// @dev override `isValidERC1271Signature` to omit staticcall
    function isValidERC1271Signature(
        address signer,
        bytes32 hash,
        bytes memory signature
    ) internal override view returns (bool isValid) {
        return ret_isValidERC1271Signature;
    }

    /// @dev override `checkVaultStatusInternal` to call `creditVaultStub`
    function checkVaultStatusInternal(address vault) internal override returns (bool isValid, bytes memory data) {
        bool success;
        (success, data) = address(creditVaultStub).call(
            abi.encodeCall(ICreditVault.checkVaultStatus, ())
        );

        if (success) (isValid, data) = abi.decode(data, (bool, bytes));
    }

    /// @dev override `checkAccountStatusInternal` to call `creditVaultStub`
    function checkAccountStatusInternal(address account) internal override returns (bool isValid, bytes memory data) {
        uint numOfControllers = accountControllers[account].numElements;
        address controller = accountControllers[account].firstElement;

        if (numOfControllers == 0) return (true, "");
        else if (numOfControllers > 1) revert CVC_ControllerViolation();

        bool success;
        // (success, data) = controller.call( // REPLACED
        //     abi.encodeCall(
        //         ICreditVault.checkAccountStatus,
        //         (account, accountCollaterals[account].get())
        //     )
        // );
        (success, data) = address(creditVaultStub).call(
            abi.encodeCall(
                ICreditVault.checkAccountStatus, 
                (account, accountCollaterals[account].get())
            )
        );

        if (success) (isValid, data) = abi.decode(data, (bool, bytes));
    }

    /// @dev override `callPermitDataInternal` to use `callHandler`
    function callPermitDataInternal(
        address targetContract,
        address signer,
        uint value,
        bytes calldata data
    )
        internal
        override
        onBehalfOfAccountContext(signer)
        returns (bool success, bytes memory result)
    {

        // (success, result) = targetContract.call{value: value}(data); // REPLACED
        // (success, result) = address(this).call{value: value}(abi.encodeCall(this.callHandler, (data)));
        success = _spoofCall(targetContract, data);
    }

    /// @dev override `impersonateInternal` to use `callHandler`
    function impersonateInternal(
        address targetContract,
        address onBehalfOfAccount,
        uint value,
        bytes calldata data
    )
        internal
        override
        onlyController(onBehalfOfAccount)
        onBehalfOfAccountContext(onBehalfOfAccount)
        returns (bool success, bytes memory result)
    {
        if (!accountCollaterals[onBehalfOfAccount].contains(targetContract)) {
            revert CVC_NotAuthorized();
        }

        // (success, result) = targetContract.call{value: value}(data); // REPLACED
        // (success, result) = address(this).call{value: value}(abi.encodeCall(this.callHandler, (data)));
        success = _spoofCall(targetContract, data);
    }

    /// @dev override `callInternal` to use `callHandler`
    function callInternal(
        address targetContract,
        address onBehalfOfAccount,
        uint value,
        bytes calldata data
    )
        internal
        override
        onlyOwnerOrOperator(onBehalfOfAccount)
        onBehalfOfAccountContext(onBehalfOfAccount)
        returns (bool success, bytes memory result)
    {
        if (targetContract == ERC1820_REGISTRY) revert CVC_InvalidAddress();

        value = value == type(uint).max ? address(this).balance : value;

        // (success, result) = targetContract.call{value: value}(data); // REPLACED
        // (success, result) = address(this).call{value: value}(abi.encodeCall(this.callHandler, (data)));
        success = _spoofCall(targetContract, data);
    }

    function _spoofCall(address targetContract, bytes calldata data) internal returns (bool success) {
        if(callHandler_doRevert) {
            success = false;
        }

        if(callHandler_doCheckMsgSender) {
            if (targetContract != callHandler_checkedMsgSender) {
                success = false;
            }
        }

        callHandler_wasHit = true;
    }

    function callHandler(bytes calldata data) external payable {
        if(callHandler_doRevert) revert();
        if(callHandler_doCheckMsgSender) require(msg.sender == callHandler_checkedMsgSender);
        callHandler_wasHit = true;
    }

    function numAccountCollaterals(address account) external view returns (uint8) {
        return accountCollaterals[account].numElements;
    }

    function numAccountControllers(address account) external view returns (uint8) {
        return accountControllers[account].numElements;
    }

    function isAccountOperator(address account, address operator) external view returns (bool) {
        return operatorLookup[account][operator] < block.timestamp ;
    }

    function getOwnerLookup(uint152 prefix) external view returns (address owner) {
        return ownerLookup[prefix];
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