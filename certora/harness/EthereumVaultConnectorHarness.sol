// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../../src/EthereumVaultConnector.sol";
import "../../src/ExecutionContext.sol";

contract EthereumVaultConnectorHarness is EthereumVaultConnector {
    using ExecutionContext for EC;
    function getExecutionContextCallDepth() external view returns (uint8) {
        return executionContext.getCallDepth();
    }

    function getExecutionContextAreChecksDeferred() external view returns (bool) {
        return executionContext.areChecksDeferred();
    }
}
