// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

interface ICVP {
    struct ExecutionContext {
        uint8 batchDepth;
        bool checksInProgressLock;
        bool impersonateLock;
        address onBehalfOfAccount;
        uint8 reserved;
    }

    struct BatchItem {
        bool allowError;
        address targetContract;
        address onBehalfOfAccount;
        uint msgValue;
        bytes data;
    }

    struct BatchResult {
        bool success;
        bytes result;
    }

    function haveCommonOwner(
        address account,
        address otherAccount
    ) external pure returns (bool);

    function getAccountOwner(address account) external view returns (address);

    function setAccountOperator(
        address account,
        address operator,
        bool isAuthorized
    ) external payable;

    function getExecutionContext(
        address controllerToCheck
    )
        external
        view
        returns (ExecutionContext memory context, bool controllerEnabled);

    function isAccountStatusCheckDeferred(
        address account
    ) external view returns (bool);

    function isVaultStatusCheckDeferred(
        address vault
    ) external view returns (bool);

    function getCollaterals(
        address account
    ) external view returns (address[] memory);

    function isCollateralEnabled(
        address account,
        address vault
    ) external view returns (bool);

    function enableCollateral(address account, address vault) external payable;

    function disableCollateral(address account, address vault) external payable;

    function getControllers(
        address account
    ) external view returns (address[] memory);

    function isControllerEnabled(
        address account,
        address vault
    ) external view returns (bool);

    function enableController(address account, address vault) external payable;

    function disableController(address account) external payable;

    function batch(BatchItem[] calldata items) external payable;

    function batchRevert(
        BatchItem[] calldata items
    )
        external
        payable
        returns (
            BatchResult[] memory batchItemsResult,
            BatchResult[] memory accountsStatusResult,
            BatchResult[] memory vaultsStatusResult
        );

    function batchSimulation(
        BatchItem[] calldata items
    )
        external
        payable
        returns (
            BatchResult[] memory batchItemsResult,
            BatchResult[] memory accountsStatusResult,
            BatchResult[] memory vaultsStatusResult
        );

    function call(
        address targetContract,
        address onBehalfOfAccount,
        bytes calldata data
    ) external payable returns (bool success, bytes memory result);

    function impersonate(
        address targetContract,
        address onBehalfOfAccount,
        bytes calldata data
    ) external payable returns (bool success, bytes memory result);

    function checkAccountStatus(
        address account
    ) external view returns (bool isValid);

    function checkAccountsStatus(
        address[] calldata accounts
    ) external view returns (bool[] memory isValid);

    function requireAccountStatusCheck(address account) external;

    function requireAccountsStatusCheck(address[] calldata accounts) external;

    function requireAccountStatusCheckNow(address account) external;

    function requireAccountsStatusCheckNow(
        address[] calldata accounts
    ) external;

    function requireVaultStatusCheck() external;

    function forgiveAccountStatusCheck(address account) external;

    function forgiveAccountsStatusCheck(address[] calldata accounts) external;
}
