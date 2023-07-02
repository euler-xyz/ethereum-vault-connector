// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../Types.sol";

interface IEulerConductor {
    function setAccountOperator(address account, address operator, bool isAuthorized) external payable;
    function getExecutionContext() external view returns (bool checksDeferred, address onBehalfOfAccount);
    function getExecutionContextExtended(address account, address vault) external view 
        returns (bool checksDeferred, address onBehalfOfAccount, bool controllerEnabled);
    function getCollaterals(address account) external view returns (address[] memory);
    function isCollateralEnabled(address account, address vault) external view returns (bool);
    function enableCollateral(address account, address vault) external payable;
    function disableCollateral(address account, address vault) external payable;
    function getControllers(address account) external view returns (address[] memory);
    function isControllerEnabled(address account, address vault) external view returns (bool);
    function enableController(address account, address vault) external payable;
    function disableController(address account, address vault) external payable;
    function batch(Types.EulerBatchItem[] calldata items) external payable;
    function batchRevert(Types.EulerBatchItem[] calldata items) external payable
        returns (Types.EulerResult[] memory batchItemsResult, Types.EulerResult[] memory accountsStatusResult, Types.EulerResult[] memory vaultsStatusResult);
    function batchSimulation(Types.EulerBatchItem[] calldata items) external payable
        returns (Types.EulerResult[] memory batchItemsResult, Types.EulerResult[] memory accountsStatusResult, Types.EulerResult[] memory vaultsStatusResult);
    function call(address targetContract, address onBehalfOfAccount, bytes calldata data) external payable
        returns (bool success, bytes memory result);
    function callFromControllerToCollateral(address targetContract, address onBehalfOfAccount, bytes calldata data) external payable
        returns (bool success, bytes memory result);
    function checkAccountStatus(address account) external view returns (bool isValid);
    function checkAccountsStatus(address[] calldata accounts) external view returns (bool[] memory isValid);
    function requireAccountStatusCheck(address account) external;
    function requireAccountsStatusCheck(address[] calldata accounts) external;
    function requireVaultStatusCheck(address vault) external;
}   
