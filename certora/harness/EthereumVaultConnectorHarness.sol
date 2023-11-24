// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../../src/EthereumVaultConnector.sol";
import "../../src/ExecutionContext.sol";

contract EthereumVaultConnectorHarness is EthereumVaultConnector {
    using ExecutionContext for EC;
    using Set for SetStorage;
    function getExecutionContextCallDepth() external view returns (uint8) {
        return executionContext.getCallDepth();
    }

    function getExecutionContextAreChecksDeferred() external view returns (bool) {
        return executionContext.areChecksDeferred();
    }

    function accountControllerContains(address base, address lookUp) public view returns (bool){
        return accountControllers[base].contains(lookUp);
    }

    function vaultStatusCheckContains(address vault) public view returns (bool){
        return vaultStatusChecks.contains(vault);
    }
    
    function getOwnerOf(uint152 prefix) public view returns (address) {
        return ownerLookup[prefix];
    }
}
