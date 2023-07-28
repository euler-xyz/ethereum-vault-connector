// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "src/CreditVaultProtocol.sol";

contract VaultMock is ICreditVault {
    ICVP public immutable cvp;

    constructor(ICVP _cvp) {
        cvp = _cvp;
    }

    function disableController(address account) public override {}

    function checkAccountStatus(
        address,
        address[] memory
    ) external pure override returns (bool, bytes memory) {
        return (true, "");
    }

    function checkVaultStatus()
        external
        pure
        override
        returns (bool, bytes memory)
    {
        return (true, "");
    }

    fallback(bytes calldata) external payable returns (bytes memory) {
        cvp.requireAccountStatusCheck(address(0));
        cvp.requireVaultStatusCheck();
        return "";
    }

    receive() external payable {}
}

contract CreditVaultProtocolHandler is CreditVaultProtocol, Test {
    using Set for SetStorage;

    address internal vaultMock;
    address[] public touchedAccounts;

    constructor() {
        vaultMock = address(new VaultMock(ICVP(address(this))));
    }

    function getTouchedAccounts() external view returns (address[] memory) {
        return touchedAccounts;
    }

    function setup(address account, address vault) internal {
        touchedAccounts.push(account);
        accountOperators[account][msg.sender] = true;
        vm.etch(vault, vaultMock.code);
    }

    function setAccountOperator(
        address account,
        address operator,
        bool isAuthorized
    ) public payable override {
        if ((uint160(msg.sender) | 0xFF) == (uint160(operator) | 0xFF)) return;
        account = msg.sender;
        super.setAccountOperator(account, operator, isAuthorized);
    }

    function enableCollateral(
        address account,
        address vault
    ) public payable override {
        if (uint160(vault) <= 10) return;
        if (vault == address(this)) return;
        setup(account, vault);
        super.enableCollateral(account, vault);
    }

    function disableCollateral(
        address account,
        address vault
    ) public payable override {
        if (uint160(vault) <= 10) return;
        if (vault == address(this)) return;
        setup(account, vault);
        super.disableCollateral(account, vault);
    }

    function enableController(
        address account,
        address vault
    ) public payable override {
        if (uint160(vault) <= 10) return;
        if (vault == address(this)) return;
        setup(account, vault);
        super.enableCollateral(account, vault);
    }

    function disableController(address account) public payable override {
        if (uint160(msg.sender) <= 10) return;
        setup(account, msg.sender);
        super.disableController(account);
    }

    function call(
        address targetContract,
        address onBehalfOfAccount,
        bytes calldata data
    ) public payable override returns (bool success, bytes memory result) {
        if (uint160(targetContract) <= 10) return (true, "");
        if (targetContract == address(this)) return (true, "");
        setup(onBehalfOfAccount, targetContract);

        (success, result) = super.call(targetContract, onBehalfOfAccount, data);
    }

    function impersonate(
        address targetContract,
        address onBehalfOfAccount,
        bytes calldata data
    ) public payable override returns (bool success, bytes memory result) {
        if (uint160(msg.sender) <= 10) return (true, "");
        if (uint160(targetContract) <= 10) return (true, "");
        if (targetContract == address(this)) return (true, "");
        setup(onBehalfOfAccount, msg.sender);
        setup(onBehalfOfAccount, targetContract);
        accountControllers[onBehalfOfAccount].insert(msg.sender);
        accountCollaterals[onBehalfOfAccount].insert(targetContract);

        (success, result) = super.impersonate(
            targetContract,
            onBehalfOfAccount,
            data
        );
    }

    function batch(BatchItem[] calldata items) public payable override {
        if (items.length > Set.MAX_ELEMENTS) return;

        for (uint i = 0; i < items.length; i++) {
            if (uint160(items[i].msgValue) > type(uint128).max) return;
            if (uint160(items[i].targetContract) <= 10) return;
            if (items[i].targetContract == address(this)) return;
        }

        vm.deal(address(this), type(uint).max);
        super.batch(items);
    }

    function batchRevert(
        BatchItem[] calldata
    )
        public
        payable
        override
        returns (
            BatchResult[] memory batchItemsResult,
            BatchResult[] memory accountsStatusResult,
            BatchResult[] memory vaultsStatusResult
        )
    {
        BatchResult[] memory x;
        return (x, x, x);
    }

    function batchSimulation(
        BatchItem[] calldata
    )
        public
        payable
        override
        returns (
            BatchResult[] memory batchItemsResult,
            BatchResult[] memory accountsStatusResult,
            BatchResult[] memory vaultsStatusResult
        )
    {
        BatchResult[] memory x;
        return (x, x, x);
    }

    function requireAccountsStatusCheck(
        address[] calldata accounts
    ) public override {
        if (accounts.length > Set.MAX_ELEMENTS) return;
        super.requireAccountsStatusCheck(accounts);
    }

    function requireAccountsStatusCheckNow(
        address[] calldata accounts
    ) public override {
        if (accounts.length > Set.MAX_ELEMENTS) return;
        super.requireAccountsStatusCheckNow(accounts);
    }

    function requireAccountStatusCheckInternal(address) internal pure override {
        return;
    }

    function requireVaultStatusCheckInternal(address) internal pure override {
        return;
    }

    function exposeAccountCollaterals(
        address account
    ) external view returns (SetStorage memory) {
        return accountControllers[account];
    }

    function exposeAccountControllers(
        address account
    ) external view returns (SetStorage memory) {
        return accountControllers[account];
    }

    function exposeTransientStorage()
        external
        view
        returns (SetStorage memory, SetStorage memory)
    {
        return (accountStatusChecks, vaultStatusChecks);
    }
}

contract CreditVaultProtocolInvariants is Test {
    CreditVaultProtocolHandler internal cvp;

    function setUp() public {
        cvp = new CreditVaultProtocolHandler();

        targetContract(address(cvp));
    }

    function invariant_invariantsCheck() external view {
        cvp.invariantsCheck();
    }

    function invariant_executionContext() external {
        (ICVP.ExecutionContext memory context, bool controllerEnabled) = cvp
            .getExecutionContext(address(this));

        assertEq(context.batchDepth, 0);
        assertFalse(context.checksLock);
        assertFalse(context.impersonateLock);
        assertEq(context.onBehalfOfAccount, address(0));
        assertFalse(controllerEnabled);
    }

    function invariant_transientStorage() external {
        (
            SetStorage memory accountStatusChecks,
            SetStorage memory vaultStatusChecks
        ) = cvp.exposeTransientStorage();

        assertTrue(accountStatusChecks.numElements == 0);
        assertTrue(accountStatusChecks.firstElement == address(0));
        assertTrue(vaultStatusChecks.numElements == 0);
        assertTrue(vaultStatusChecks.firstElement == address(0));
    }

    function invariant_controllers_collaterals() external {
        address[] memory touchedAccounts = cvp.getTouchedAccounts();
        for (uint i = 0; i < touchedAccounts.length; i++) {
            // controllers
            SetStorage memory accountControllers = cvp.exposeAccountControllers(
                touchedAccounts[i]
            );
            address[] memory accountControllersArray = cvp.getControllers(
                touchedAccounts[i]
            );

            assertTrue(
                accountControllers.numElements == 0 ||
                    accountControllers.numElements == 1
            );
            assertTrue(
                (accountControllers.numElements == 0 &&
                    accountControllers.firstElement == address(0)) ||
                    (accountControllers.numElements == 1 &&
                        accountControllers.firstElement != address(0))
            );

            for (uint j = 1; j < accountControllersArray.length; j++) {
                assertTrue(accountControllersArray[j] == address(0));
            }

            // collaterals
            SetStorage memory accountCollaterals = cvp.exposeAccountCollaterals(
                touchedAccounts[i]
            );
            address[] memory accountCollateralsArray = cvp.getCollaterals(
                touchedAccounts[i]
            );

            assertTrue(accountCollaterals.numElements <= Set.MAX_ELEMENTS);
            assertTrue(
                (accountCollaterals.numElements == 0 &&
                    accountCollaterals.firstElement == address(0)) ||
                    (accountCollaterals.numElements == 1 &&
                        accountCollaterals.firstElement != address(0))
            );

            for (uint j = 0; j < accountCollateralsArray.length; j++) {
                assertTrue(accountCollateralsArray[j] != address(0));
            }

            // verify that none entry is duplicated
            for (uint j = 1; j < accountCollateralsArray.length; j++) {
                for (uint k = 0; k < j; k++) {
                    assertTrue(
                        accountCollateralsArray[j] != accountCollateralsArray[k]
                    );
                }
            }
        }
    }
}
