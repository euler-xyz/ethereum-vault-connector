// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../../src/EthereumVaultConnector.sol";
import "../../src/ExecutionContext.sol";

contract EthereumVaultConnectorHarness is EthereumVaultConnector {
    using ExecutionContext for EC;
    using Set for SetStorage;

    function getExecutionContextDefault() external view returns (uint256) {
        return EC.unwrap(ExecutionContext.initialize());
    }

    function getExecutionContextCallDepth() external view returns (uint8) {
        return executionContext.getCallDepth();
    }

    function getExecutionContextAreChecksDeferred() external view returns (bool) {
        return executionContext.areChecksDeferred();
    }
    
    function numOfController(address account) public view returns (uint8) {
        return accountControllers[account].numElements;
    }

    function getExecutionContextOnBehalfOfAccount() external view returns (address) {
        return executionContext.getOnBehalfOfAccount();
    }

    function getOwnerOf(uint152 prefix) public view returns (address) {
        return ownerLookup[prefix];
    }

    function areAccountStatusChecksEmpty() public view returns (bool) {
        return accountStatusChecks.numElements == 0;
    }
    function areVaultStatusChecksEmpty() public view returns (bool) {
        return vaultStatusChecks.numElements == 0;
    }
}
