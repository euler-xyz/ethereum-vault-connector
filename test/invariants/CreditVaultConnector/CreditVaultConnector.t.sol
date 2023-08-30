// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "src/test/CreditVaultConnectorScribble.sol";

contract VaultMock is ICreditVault {
    ICVC public immutable cvc;

    constructor(ICVC _cvc) {
        cvc = _cvc;
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
        cvc.requireAccountStatusCheck(address(0));
        cvc.requireVaultStatusCheck();
        return "";
    }

    receive() external payable {}
}

contract CreditVaultConnectorHandler is CreditVaultConnectorScribble, Test {
    using Set for SetStorage;

    address internal vaultMock;
    address[] public touchedAccounts;

    constructor() {
        vaultMock = address(new VaultMock(ICVC(address(this))));
    }

    function getTouchedAccounts() external view returns (address[] memory) {
        return touchedAccounts;
    }

    function setup(address account, address vault) internal {
        touchedAccounts.push(account);
        operatorLookup[account][msg.sender].authExpiryTimestamp = uint40(
            block.timestamp + 10
        );
        vm.etch(vault, vaultMock.code);
    }

    function invalidateAllPermits() public payable override {
        ownerLookup[getPrefixInternal(msg.sender)].owner = msg.sender;
        super.invalidateAllPermits();
    }

    /// @inheritdoc ICVC
    function invalidateAccountOperatorPermits(
        address account,
        address operator
    ) public payable override {
        ownerLookup[getPrefixInternal(account)].owner = msg.sender;
        account = msg.sender;
        super.invalidateAccountOperatorPermits(account, operator);
    }

    function setAccountOperator(
        address account,
        address operator,
        uint40 authExpiryTimestamp
    ) public payable override {
        if (haveCommonOwnerInternal(msg.sender, operator)) return;
        account = msg.sender;
        ownerLookup[getPrefixInternal(account)].owner = msg.sender;
        super.setAccountOperator(account, operator, authExpiryTimestamp);
    }

    function setAccountOperatorPermitECDSA(
        address account,
        address operator,
        uint40 authExpiryTimestamp,
        uint40,
        uint40,
        bytes calldata
    ) public payable override {
        if (haveCommonOwnerInternal(msg.sender, operator)) return;
        account = msg.sender;
        ownerLookup[getPrefixInternal(account)].owner = msg.sender;
        super.setAccountOperator(account, operator, authExpiryTimestamp);
    }

    function setAccountOperatorPermitERC1271(
        address account,
        address operator,
        uint40 authExpiryTimestamp,
        uint40,
        uint40,
        bytes calldata,
        address
    ) public payable override {
        if (haveCommonOwnerInternal(msg.sender, operator)) return;
        account = msg.sender;
        ownerLookup[getPrefixInternal(account)].owner = msg.sender;
        super.setAccountOperator(account, operator, authExpiryTimestamp);
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

    function callInternal(
        address targetContract,
        address onBehalfOfAccount,
        uint value,
        bytes calldata data
    ) internal override returns (bool success, bytes memory result) {
        if (uint160(targetContract) <= 10) return (true, "");
        if (targetContract == 0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24)
            return (true, "");
        setup(onBehalfOfAccount, targetContract);

        (success, result) = super.callInternal(
            targetContract,
            onBehalfOfAccount,
            value,
            data
        );
    }

    function impersonate(
        address targetContract,
        address onBehalfOfAccount,
        bytes calldata data
    ) public payable override returns (bool success, bytes memory result) {
        if (uint160(msg.sender) <= 10) return (true, "");
        if (uint160(targetContract) <= 10) return (true, "");
        if (targetContract == address(this)) return (true, "");

        if (onBehalfOfAccount == address(0)) {
            onBehalfOfAccount = msg.sender;
        }

        setup(onBehalfOfAccount, msg.sender);
        setup(onBehalfOfAccount, targetContract);

        accountCollaterals[onBehalfOfAccount].insert(targetContract);

        SetStorage memory cache = accountControllers[onBehalfOfAccount];
        accountControllers[onBehalfOfAccount].numElements = 1;
        accountControllers[onBehalfOfAccount].firstElement = msg.sender;

        (success, result) = super.impersonate(
            targetContract,
            onBehalfOfAccount,
            data
        );

        accountControllers[onBehalfOfAccount] = cache;
    }

    function batch(BatchItem[] calldata items) public payable override {
        if (items.length > Set.MAX_ELEMENTS) return;

        for (uint i = 0; i < items.length; i++) {
            if (uint160(items[i].value) > type(uint128).max) return;
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
            BatchItemResult[] memory batchItemsResult,
            BatchItemResult[] memory accountsStatusResult,
            BatchItemResult[] memory vaultsStatusResult
        )
    {
        BatchItemResult[] memory x = new BatchItemResult[](0);
        return (x, x, x);
    }

    function batchSimulation(
        BatchItem[] calldata
    )
        public
        payable
        override
        returns (
            BatchItemResult[] memory batchItemsResult,
            BatchItemResult[] memory accountsStatusResult,
            BatchItemResult[] memory vaultsStatusResult
        )
    {
        BatchItemResult[] memory x = new BatchItemResult[](0);
        return (x, x, x);
    }

    function forgiveAccountStatusCheck(
        address account
    ) public payable override {
        if (msg.sender == address(0)) return;

        SetStorage memory cache = accountControllers[account];
        accountControllers[account].numElements = 1;
        accountControllers[account].firstElement = msg.sender;

        super.forgiveAccountStatusCheck(account);

        accountControllers[account] = cache;
    }

    function forgiveAccountsStatusCheck(
        address[] calldata accounts
    ) public payable override {
        if (msg.sender == address(0)) return;
        if (accounts.length > Set.MAX_ELEMENTS) return;

        SetStorage[] memory cache = new SetStorage[](accounts.length);
        for (uint i = 0; i < accounts.length; i++) {
            address account = accounts[i];
            cache[i] = accountControllers[account];
            accountControllers[account].numElements = 1;
            accountControllers[account].firstElement = msg.sender;
        }

        super.forgiveAccountsStatusCheck(accounts);

        for (uint i = accounts.length; i > 0; i--) {
            address account = accounts[i - 1];
            accountControllers[account] = cache[i - 1];
        }
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
        return accountCollaterals[account];
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

contract CreditVaultConnectorInvariants is Test {
    CreditVaultConnectorHandler internal cvc;

    function setUp() public {
        cvc = new CreditVaultConnectorHandler();

        targetContract(address(cvc));
    }

    function invariant_executionContext() external {
        (ICVC.ExecutionContext memory context, bool controllerEnabled) = cvc
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
        ) = cvc.exposeTransientStorage();

        assertTrue(accountStatusChecks.numElements == 0);
        assertTrue(vaultStatusChecks.numElements == 0);
    }

    function invariant_controllers_collaterals() external {
        address[] memory touchedAccounts = cvc.getTouchedAccounts();
        for (uint i = 0; i < touchedAccounts.length; i++) {
            // controllers
            SetStorage memory accountControllers = cvc.exposeAccountControllers(
                touchedAccounts[i]
            );
            address[] memory accountControllersArray = cvc.getControllers(
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
            SetStorage memory accountCollaterals = cvc.exposeAccountCollaterals(
                touchedAccounts[i]
            );
            address[] memory accountCollateralsArray = cvc.getCollaterals(
                touchedAccounts[i]
            );

            assertTrue(accountCollaterals.numElements <= Set.MAX_ELEMENTS);
            assertTrue(
                (accountCollaterals.numElements == 0 &&
                    accountCollaterals.firstElement == address(0)) ||
                    (accountCollaterals.numElements == 1 &&
                        accountCollaterals.firstElement != address(0))
            );

            for (uint j = 1; j < accountCollaterals.numElements; j++) {
                assertTrue(accountCollateralsArray[j] != address(0));
            }

            // verify that none entry is duplicated
            for (uint j = 1; j < accountCollaterals.numElements; j++) {
                for (uint k = 0; k < j; k++) {
                    assertTrue(
                        accountCollateralsArray[j] != accountCollateralsArray[k]
                    );
                }
            }
        }
    }
}
