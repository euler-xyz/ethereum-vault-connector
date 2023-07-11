// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "../Types.sol";

interface ICVP {
    function setAccountOperator(address account, address operator, bool isAuthorized) external payable;
    function getExecutionContext(address controllerToCheck) external view 
    returns (address onBehalfOfAccount, bool controllerEnabled, bool checksDeferred);
    function isAccountStatusCheckDeferred(address account) external view returns (bool);
    function isVaultStatusCheckDeferred(address vault) external view returns (bool);
    function getCollaterals(address account) external view returns (address[] memory);
    function isCollateralEnabled(address account, address vault) external view returns (bool);
    function enableCollateral(address account, address vault) external payable;
    function disableCollateral(address account, address vault) external payable;
    function getController(address account) external view returns (address);
    function isControllerEnabled(address account, address vault) external view returns (bool);
    function enableController(address account, address vault) external payable;
    function disableController(address account) external payable;
    function batch(Types.BatchItem[] calldata items) external payable;
    function batchRevert(Types.BatchItem[] calldata items) external payable
        returns (Types.BatchResult[] memory batchItemsResult, Types.BatchResult[] memory accountsStatusResult, Types.BatchResult[] memory vaultsStatusResult);
    function batchSimulation(Types.BatchItem[] calldata items) external payable
        returns (Types.BatchResult[] memory batchItemsResult, Types.BatchResult[] memory accountsStatusResult, Types.BatchResult[] memory vaultsStatusResult);
    function call(address targetContract, address onBehalfOfAccount, bytes calldata data) external payable
        returns (bool success, bytes memory result);
    function callFromControllerToCollateral(address targetContract, address onBehalfOfAccount, bytes calldata data) external payable
        returns (bool success, bytes memory result);
    function checkAccountStatus(address account) external view returns (bool isValid);
    function checkAccountsStatus(address[] calldata accounts) external view returns (bool[] memory isValid);
    function requireAccountStatusCheck(address account) external;
    function requireAccountsStatusCheck(address[] calldata accounts) external;
    function requireVaultStatusCheck() external;
}   
