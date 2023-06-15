// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/EulerConductor.sol";
import "../src/Types.sol";
import "../src/Array.sol";

contract TargetMock {
    function executeExample(
        address conductor,
        bool expectedChecksDeferred,
        Types.EulerBatchItem memory item
    ) external payable {
        address onBehalfOfAccount;
        bool checksDeferred;
        assembly {
            onBehalfOfAccount := shr(96, calldataload(sub(calldatasize(), 40)))
            checksDeferred := shr(96, calldataload(sub(calldatasize(), 1)))
        }

        require(msg.sender == conductor, "executeExample/invalid-sender");
        require(
            onBehalfOfAccount == item.onBehalfOfAccount,
            "executeExample/invalid-on-behalf-of-account"
        );
        require(
            address(this) == item.targetContract,
            "executeExample/invalid-target-contract"
        );
        require(msg.value == item.msgValue, "executeExample/invalid-msg-value");
        require(
            checksDeferred == expectedChecksDeferred,
            "executeExample/invalid-checks-deferred"
        );
    }
}

contract EulerRegistryMock is IEulerVaultRegistry {
    mapping(address => bool) public isRegistered;

    function setRegistered(address vault, bool registered) external {
        isRegistered[vault] = registered;
    }
}

contract EulerVaultMock is IEulerVault, TargetMock, Test {
    uint internal accountStatusState;
    address[] internal accountStatusChecked;
    uint[] internal hooksCalled;

    function setAccountStatusState(uint state) external {
        accountStatusState = state;
    }

    function reset() external {
        accountStatusState = 0;

        delete accountStatusChecked;
        delete hooksCalled;
    }

    function pushAccountStatusChecked(address account) external {
        accountStatusChecked.push(account);
    }

    function getAccountStatusChecked()
        external
        view
        returns (address[] memory)
    {
        return accountStatusChecked;
    }

    function getHooksCalled() external view returns (uint[] memory) {
        return hooksCalled;
    }

    function checkAccountStatus(
        address,
        address[] memory
    ) external view returns (bool isValid) {
        if (accountStatusState == 0) return true;
        else if (accountStatusState == 1) return false;
        else revert("invalid");
    }

    function hook(
        uint hookNumber,
        bytes memory data
    ) external returns (bytes memory result) {
        if (hookNumber == 0) {
            if (abi.decode(data, (uint)) != 0) revert HookViolation("hook/1/violation");
        } else if (hookNumber == 1) {
            if (abi.decode(data, (uint)) != 1) revert HookViolation("hook/2/violation");
        } else {
            revert("unexpected hook number");
        }

        hooksCalled.push(hookNumber);
        return abi.encode(abi.decode(data, (uint)) + 1);
    }

    function call(address target, bytes memory data) external payable {
        (bool success, ) = target.call{value: msg.value}(data);
        require(success, "call/failed");
    }
}

contract EulerConductorHandler is EulerConductor {
    struct AccountStatusCheck {
        address vault;
        address[] accounts;
    }

    struct VaultStatusCheck {
        address vault;
        uint[] hooks;
    }

    using Array for Types.ArrayStorage;
    Types.ArrayStorage internal helperArray;

    constructor(
        address admin,
        address registry
    ) EulerConductor(admin, registry) {}

    function setChecksDeferred(bool deferred) external {
        checksDeferred = deferred;
    }

    function requireAccountStatusCheckInternal(
        address account
    ) internal override {
        super.requireAccountStatusCheckInternal(account);

        address[] memory controllers = accountControllers[account].getArray();
        if (controllers.length == 1)
            EulerVaultMock(controllers[0]).pushAccountStatusChecked(account);
    }

    function verifyTransientStorage(
        VaultStatusCheck[] memory vsc
    ) internal view {
        require(!checksDeferred, "verifyTransientStorage/checks-deferred");
        require(
            accountStatusChecks.numElements == 0,
            "verifyTransientStorage/account-status-checks/numElements"
        );
        require(
            accountStatusChecks.firstElement == address(0),
            "verifyTransientStorage/account-status-checks/firstElement"
        );

        for (uint i = 0; i < 20; ++i) {
            require(
                accountStatusChecks.elements[i] == address(0),
                "verifyTransientStorage/account-status-checks/elements"
            );
        }

        require(
            vaultStatusChecks.numElements == 0,
            "verifyTransientStorage/vault-status-checks/numElements"
        );
        require(
            vaultStatusChecks.firstElement == address(0),
            "verifyTransientStorage/vault-status-checks/firstElement"
        );

        for (uint i = 0; i < 20; ++i) {
            require(
                vaultStatusChecks.elements[i] == address(0),
                "verifyTransientStorage/vault-status-checks/elements"
            );
        }

        for (uint i = 0; i < vsc.length; ++i) {
            require(
                vaultStatuses[vsc[i].vault].length == 0,
                "verifyTransientStorage/vault-statuses"
            );
        }
    }

    function verifyVaultStatusChecks(
        VaultStatusCheck[] memory vsc
    ) internal view {
        for (uint i = 0; i < vsc.length; ++i) {
            uint[] memory hooks = EulerVaultMock(vsc[i].vault).getHooksCalled();

            require(
                hooks.length == vsc[i].hooks.length,
                "verifyVaultStatusChecks/length"
            );

            if (hooks.length == 2) {
                if (hooks[0] == vsc[i].hooks[0]) {
                    require(
                        hooks[1] == vsc[i].hooks[1],
                        "verifyVaultStatusChecks/1=1/hook"
                    );
                } else {
                    require(
                        hooks[0] == vsc[i].hooks[1],
                        "verifyVaultStatusChecks/0=1/hook"
                    );
                    require(
                        hooks[1] == vsc[i].hooks[0],
                        "verifyVaultStatusChecks/1=0/hook"
                    );
                }
            } else if (hooks.length == 1) {
                require(
                    hooks[0] == vsc[i].hooks[0],
                    "verifyVaultStatusChecks/0=0/hook"
                );
            } else {
                revert("unexpected number of hooks called");
            }
        }
    }

    function verifyAccountStatusChecks(
        AccountStatusCheck[] memory asc
    ) internal {
        for (uint i = 0; i < asc.length; ++i) {
            address[] memory accounts = EulerVaultMock(asc[i].vault)
                .getAccountStatusChecked();

            require(
                accounts.length == asc[i].accounts.length,
                "verifyAccountStatusChecks/length"
            );

            // copy the accounts to the helper array
            for (uint j = 0; j < accounts.length; ++j) {
                require(
                    helperArray.doAddElement(accounts[j]),
                    "verifyAccountStatusChecks/add"
                );
            }

            for (uint j = 0; j < asc[i].accounts.length; ++j) {
                require(
                    helperArray.doRemoveElement(asc[i].accounts[j]),
                    "verifyAccountStatusChecks/remove"
                );
            }
        }
    }

    function collateralControllerChecks(address account) internal {
        if (checksDeferred) return;

        address[] memory controllers = accountControllers[account].getArray();

        require(controllers.length <= 1, "collateralControllerChecks/length");

        if (controllers.length == 0) return;

        AccountStatusCheck[] memory asc = new AccountStatusCheck[](1);
        VaultStatusCheck[] memory vsc = new VaultStatusCheck[](0);

        asc[0].vault = controllers[0];
        asc[0].accounts = new address[](1);
        asc[0].accounts[0] = account;

        verifyTransientStorage(vsc);
        verifyAccountStatusChecks(asc);
    }

    function handlerEnableCollateral(address account, address vault) external {
        super.enableCollateral(account, vault);

        collateralControllerChecks(account);
    }

    function handlerDisableCollateral(address account, address vault) external {
        super.disableCollateral(account, vault);

        collateralControllerChecks(account);
    }

    function handlerEnableController(address account, address vault) external {
        super.enableController(account, vault);

        collateralControllerChecks(account);
    }

    function handlerDisableController(address account, address vault) external {
        super.disableController(account, vault);

        collateralControllerChecks(account);
    }

    function handlerBatchDispatch(
        EulerBatchItem[] calldata items,
        bool isSimulation,
        AccountStatusCheck[] memory asc,
        VaultStatusCheck[] memory vsc
    )
        public
        payable
        returns (EulerBatchItemSimulationResult[] memory simulation)
    {
        simulation = super.batchDispatch(items, isSimulation);

        verifyTransientStorage(vsc);
        verifyVaultStatusChecks(vsc);
        verifyAccountStatusChecks(asc);
    }

    function handlerBatchDispatchSimulate(
        EulerBatchItem[] calldata items,
        AccountStatusCheck[] memory asc,
        VaultStatusCheck[] memory vsc
    )
        public
        payable
        returns (EulerBatchItemSimulationResult[] memory simulation)
    {
        simulation = super.batchDispatchSimulate(items);

        verifyTransientStorage(vsc);
        verifyVaultStatusChecks(vsc);
        verifyAccountStatusChecks(asc);
    }

    function handlerExecute(
        address targetContract,
        address onBehalfOfAccount,
        bytes calldata data
    ) public payable returns (bool success, bytes memory result) {
        (success, result) = super.execute(targetContract, onBehalfOfAccount, data);

        if (!checksDeferred) {
            address[] memory controllers = accountControllers[onBehalfOfAccount]
                .getArray();

            require(controllers.length <= 1, "handlerExecute/length");

            if (controllers.length == 1) {
                AccountStatusCheck[] memory asc = new AccountStatusCheck[](1);

                asc[0].vault = targetContract;
                asc[0].accounts = new address[](1);
                asc[0].accounts[0] = onBehalfOfAccount;

                verifyAccountStatusChecks(asc);
            }
        }

        if (
            !checksDeferred &&
            EulerRegistryMock(eulerVaultRegistry).isRegistered(targetContract)
        ) {
            VaultStatusCheck[] memory vsc = new VaultStatusCheck[](1);

            vsc[0].vault = targetContract;
            vsc[0].hooks = new uint[](2);
            vsc[0].hooks[0] = 0;
            vsc[0].hooks[1] = 1;

            verifyTransientStorage(vsc);
            verifyVaultStatusChecks(vsc);
        } else {
            VaultStatusCheck[] memory vsc = new VaultStatusCheck[](1);
            vsc[0].vault = targetContract;

            verifyTransientStorage(vsc);
        }
    }

    function handlerForward(
        address targetContract,
        address onBehalfOfAccount,
        bytes calldata data
    ) public payable returns (bool success, bytes memory result) {
        (success, result) = super.forward(targetContract, onBehalfOfAccount, data);

        if (!checksDeferred) {
            AccountStatusCheck[] memory asc = new AccountStatusCheck[](1);
            VaultStatusCheck[] memory vsc = new VaultStatusCheck[](1);

            asc[0].vault = targetContract;
            asc[0].accounts = new address[](1);
            asc[0].accounts[0] = onBehalfOfAccount;

            vsc[0].vault = targetContract;
            vsc[0].hooks = new uint[](2);
            vsc[0].hooks[0] = 0;
            vsc[0].hooks[1] = 1;

            verifyTransientStorage(vsc);
            verifyVaultStatusChecks(vsc);
            verifyAccountStatusChecks(asc);
        }
    }
}

contract EulerConductorTest is Test {
    address owner = makeAddr("owner");
    EulerConductorHandler conductor;
    address registry;

    function samePrimaryAccount(
        address accountOne,
        address accountTwo
    ) internal pure returns (bool) {
        return (uint160(accountOne) | 0xFF) == (uint160(accountTwo) | 0xFF);
    }

    function setUp() public {
        registry = address(new EulerRegistryMock());
        conductor = new EulerConductorHandler(owner, registry);
    }

    function test_SetGovernorAdmin(address newOwner) public {
        assertEq(conductor.governorAdmin(), owner);

        vm.prank(owner);
        //vm.expectEmit(address(true, false, false, false, conductor));
        //emit EulerConductor.GovernorAdminSet(newOwner);
        conductor.setGovernorAdmin(newOwner);

        assertEq(conductor.governorAdmin(), newOwner);
    }

    function test_SetGovernorAdmin_RevertIfNotGovernor(
        address newOwner,
        address notOwner
    ) public {
        vm.assume(notOwner != owner);

        assertEq(conductor.governorAdmin(), owner);

        vm.prank(notOwner);
        vm.expectRevert(EulerConductor.NotAuthorized.selector);
        conductor.setGovernorAdmin(newOwner);
    }

    function test_SetEulerVaultRegistry(address newRegistry) public {
        vm.assume(newRegistry != address(0));

        assertEq(conductor.eulerVaultRegistry(), registry);

        vm.prank(owner);
        //vm.expectEmit(address(true, false, false, false, conductor));
        //emit EulerConductor.EulerVaultRegistrySet(newRegistry);
        conductor.setEulerVaultRegistry(newRegistry);

        assertEq(conductor.eulerVaultRegistry(), newRegistry);
    }

    function test_SetEulerVaultRegistry_RevertIfNotGovernor(
        address newRegistry,
        address notOwner
    ) public {
        vm.assume(notOwner != owner && newRegistry != address(0));

        assertEq(conductor.eulerVaultRegistry(), registry);

        vm.prank(notOwner);
        vm.expectRevert(EulerConductor.NotAuthorized.selector);
        conductor.setEulerVaultRegistry(newRegistry);
    }

    function test_SetEulerVaultRegistry_RevertIfZeroAddress() public {
        assertEq(conductor.eulerVaultRegistry(), registry);

        vm.prank(owner);
        vm.expectRevert(EulerConductor.InvalidAddress.selector);
        conductor.setEulerVaultRegistry(address(0));
    }

    function test_SetAccountOperator(address alice, address operator) public {
        vm.assume(!samePrimaryAccount(alice, operator));

        for (uint i = 0; i < 256; ++i) {
            address account = address(uint160(uint160(alice) ^ i));

            assertFalse(conductor.accountOperators(account, operator));

            vm.prank(alice);
            //vm.expectEmit(address(true, true, false, true, conductor));
            //emit EulerConductor.AccountOperatorSet(account, operator, true);
            conductor.setAccountOperator(account, operator, true);

            assertTrue(conductor.accountOperators(account, operator));

            vm.prank(alice);
            //vm.expectEmit(address(true, true, false, true, conductor));
            //emit EulerConductor.AccountOperatorSet(account, operator, false);
            conductor.setAccountOperator(account, operator, false);

            assertFalse(conductor.accountOperators(account, operator));
        }
    }

    function test_SetAccountOperator_RevertIfSenderNotAuthorized(
        address alice,
        address operator
    ) public {
        vm.assume(!samePrimaryAccount(alice, operator));

        address account = address(uint160(uint160(alice) ^ 256));

        assertFalse(conductor.accountOperators(account, operator));

        vm.prank(alice);
        vm.expectRevert(EulerConductor.NotAuthorized.selector);
        conductor.setAccountOperator(account, operator, true);
    }

    function test_SetAccountOperator_RevertIfOperatorIsSenderSubAccount(
        address alice,
        uint8 subAccountId
    ) public {
        address operator = address(uint160(uint160(alice) ^ subAccountId));

        assertFalse(conductor.accountOperators(alice, operator));

        vm.prank(alice);
        vm.expectRevert(EulerConductor.InvalidAddress.selector);
        conductor.setAccountOperator(alice, operator, true);
    }

    function test_GetCollaterals(address alice) public {
        conductor.setChecksDeferred(false);
        conductor.getCollaterals(alice);
    }

    function test_GetCollaterals_RevertIfChecksDeferred(address alice) public {
        conductor.setChecksDeferred(true);
        vm.expectRevert(EulerConductor.DeferralViolation.selector);
        conductor.getCollaterals(alice);
    }

    function test_IsCollateralEnabled(address alice, address vault) public {
        conductor.setChecksDeferred(false);
        conductor.isCollateralEnabled(alice, vault);
    }

    function test_IsCollateralEnabled_RevertIfChecksDeferred(
        address alice,
        address vault
    ) public {
        conductor.setChecksDeferred(true);
        vm.expectRevert(EulerConductor.DeferralViolation.selector);
        conductor.isCollateralEnabled(alice, vault);
    }

    function test_CollateralsManagement(
        address alice,
        uint8 subAccountId,
        uint8 numberOfVaults,
        uint seed
    ) public {
        vm.assume(numberOfVaults <= 20);
        vm.assume(seed > 1000);

        address account = address(uint160(uint160(alice) ^ subAccountId));

        // test collaterals management with use of an operator
        address msgSender = alice;
        if (
            seed % 2 == 0 &&
            !samePrimaryAccount(account, address(uint160(seed)))
        ) {
            msgSender = address(uint160(seed));
            vm.prank(alice);
            conductor.setAccountOperator(account, msgSender, true);
        }

        // enable a controller to check if account status check works properly
        address controller = address(new EulerVaultMock());
        if (seed % 3 == 0) {
            EulerRegistryMock(registry).setRegistered(controller, true);

            vm.prank(alice);
            conductor.enableController(account, controller);
        }

        // enabling collaterals
        for (uint i = 1; i <= numberOfVaults; ++i) {
            EulerVaultMock(controller).reset();
            address[] memory collateralsPre = conductor.getCollaterals(
                account
            );

            address vault = i % 5 == 0
                ? collateralsPre[seed % collateralsPre.length]
                : address(new EulerVaultMock());

            EulerRegistryMock(registry).setRegistered(vault, true);
            bool alreadyEnabled = conductor.isCollateralEnabled(
                account,
                vault
            );

            assert(
                (alreadyEnabled && i % 5 == 0) ||
                    (!alreadyEnabled && i % 5 != 0)
            );

            vm.prank(msgSender);
            conductor.handlerEnableCollateral(account, vault);

            address[] memory collateralsPost = conductor.getCollaterals(
                account
            );

            if (alreadyEnabled) {
                assertEq(collateralsPost.length, collateralsPre.length);
            } else {
                assertEq(collateralsPost.length, collateralsPre.length + 1);
                assertEq(collateralsPost[collateralsPost.length - 1], vault);
            }

            for (uint j = 0; j < collateralsPre.length; ++j) {
                assertEq(collateralsPre[j], collateralsPost[j]);
            }
        }

        // disabling collaterals
        while (conductor.getCollaterals(account).length > 0) {
            EulerVaultMock(controller).reset();
            address[] memory collateralsPre = conductor.getCollaterals(
                account
            );
            address vault = collateralsPre[seed % collateralsPre.length];

            vm.prank(msgSender);
            conductor.handlerDisableCollateral(account, vault);

            address[] memory collateralsPost = conductor.getCollaterals(
                account
            );

            assertEq(collateralsPost.length, collateralsPre.length - 1);

            for (uint j = 0; j < collateralsPost.length; ++j) {
                assertNotEq(collateralsPost[j], vault);
            }
        }
    }

    function test_CollateralsManagement_RevertIfNotOwnerAndNotOperator(
        address alice,
        address bob
    ) public {
        vm.assume(!samePrimaryAccount(alice, bob));

        address vault = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(vault, true);

        vm.prank(alice);
        vm.expectRevert(EulerConductor.NotAuthorized.selector);
        conductor.handlerEnableCollateral(bob, vault);

        vm.prank(alice);
        vm.expectRevert(EulerConductor.NotAuthorized.selector);
        conductor.handlerDisableCollateral(bob, vault);

        vm.prank(bob);
        conductor.setAccountOperator(bob, alice, true);

        vm.prank(alice);
        conductor.handlerEnableCollateral(bob, vault);

        vm.prank(alice);
        conductor.handlerDisableCollateral(bob, vault);
    }

    function test_CollateralsManagement_RevertIfVaultNotRegistered(
        address alice
    ) public {
        address vault = address(new EulerVaultMock());

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                EulerConductor.VaultNotRegistered.selector,
                vault
            )
        );
        conductor.handlerEnableCollateral(alice, vault);

        vm.prank(alice);
        // does not revert. because only registered collaterals can be enabled it doesn't check for registration here
        conductor.handlerDisableCollateral(alice, vault);

        EulerRegistryMock(registry).setRegistered(vault, true);

        vm.prank(alice);
        conductor.handlerEnableCollateral(alice, vault);

        vm.prank(alice);
        conductor.handlerDisableCollateral(alice, vault);
    }

    function test_CollateralsManagement_RevertIfAccountStatusViolated(
        address alice
    ) public {
        address vault = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(vault, true);

        address controller = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(controller, true);

        vm.prank(alice);
        conductor.enableController(alice, controller);
        EulerVaultMock(controller).reset();

        EulerVaultMock(controller).setAccountStatusState(1); // account status is violated

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                EulerConductor.AccountStatusViolation.selector,
                alice
            )
        );
        conductor.handlerEnableCollateral(alice, vault);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                EulerConductor.AccountStatusViolation.selector,
                alice
            )
        );
        conductor.handlerDisableCollateral(alice, vault);

        EulerVaultMock(controller).setAccountStatusState(0); // account status is NOT violated

        vm.prank(alice);
        conductor.handlerEnableCollateral(alice, vault);
        EulerVaultMock(controller).reset(); // reset so that the account status check verification succeeds

        vm.prank(alice);
        conductor.handlerDisableCollateral(alice, vault);
    }

    function test_GetControllers(address alice) public {
        conductor.setChecksDeferred(false);
        conductor.getControllers(alice);
    }

    function test_GetControllers_RevertIfChecksDeferred(address alice) public {
        conductor.setChecksDeferred(true);
        vm.expectRevert(EulerConductor.DeferralViolation.selector);
        conductor.getControllers(alice);
    }

    function test_IsControllerEnabled(address alice) public {
        address vault = address(new EulerVaultMock());
        conductor.setChecksDeferred(false);
        conductor.isControllerEnabled(alice, vault);

        // even though checks are deferred, the function succeeds if called by the vault asking if vault enabled
        // as a controller
        conductor.setChecksDeferred(true);
        EulerVaultMock(vault).call(
            address(conductor),
            abi.encodeWithSelector(
                EulerConductor.isControllerEnabled.selector,
                alice,
                vault
            )
        );
    }

    function test_IsControllerEnabled_RevertIfChecksDeferredAndMsgSenderNotVault(
        address alice,
        address vault
    ) public {
        vm.assume(address(this) != vault);

        conductor.setChecksDeferred(true);
        vm.expectRevert(EulerConductor.DeferralViolation.selector);
        conductor.isControllerEnabled(alice, vault);
    }

    function test_ControllersManagement(
        address alice,
        uint8 subAccountId,
        uint seed
    ) public {
        vm.assume(seed > 1000);

        address account = address(uint160(uint160(alice) ^ subAccountId));

        // test controllers management with use of an operator
        address msgSender = alice;
        if (
            seed % 2 == 0 &&
            !samePrimaryAccount(account, address(uint160(seed)))
        ) {
            msgSender = address(uint160(seed));
            vm.prank(alice);
            conductor.setAccountOperator(account, msgSender, true);
        }

        // enabling controller
        address vault = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(vault, true);

        assertFalse(conductor.isControllerEnabled(account, vault));
        address[] memory controllersPre = conductor.getControllers(account);

        vm.prank(msgSender);
        conductor.handlerEnableController(account, vault);

        address[] memory controllersPost = conductor.getControllers(account);

        assertEq(controllersPost.length, controllersPre.length + 1);
        assertEq(controllersPost[controllersPost.length - 1], vault);
        assertTrue(conductor.isControllerEnabled(account, vault));

        // enabling the same controller again should succeed (duplicate will not be added)
        EulerVaultMock(vault).reset();
        assertTrue(conductor.isControllerEnabled(account, vault));
        controllersPre = conductor.getControllers(account);

        vm.prank(msgSender);
        conductor.handlerEnableController(account, vault);

        controllersPost = conductor.getControllers(account);

        assertEq(controllersPost.length, controllersPre.length);
        assertEq(controllersPost[0], controllersPre[0]);
        assertTrue(conductor.isControllerEnabled(account, vault));

        // trying to enable second controller will throw on the account status check if checks are not deferred
        address otherVault = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(otherVault, true);

        vm.prank(msgSender);
        vm.expectRevert(
            abi.encodeWithSelector(
                EulerConductor.ControllerViolation.selector,
                account
            )
        );
        conductor.handlerEnableController(account, otherVault);

        // only the controller vault can disable itself
        EulerVaultMock(vault).reset();
        assertTrue(conductor.isControllerEnabled(account, vault));
        controllersPre = conductor.getControllers(account);

        vm.prank(msgSender);
        EulerVaultMock(vault).call(
            address(conductor),
            abi.encodeWithSelector(
                EulerConductorHandler.handlerDisableController.selector,
                account,
                vault
            )
        );

        controllersPost = conductor.getControllers(account);

        assertEq(controllersPost.length, controllersPre.length - 1);
        assertEq(controllersPost.length, 0);
        assertFalse(conductor.isControllerEnabled(account, vault));
    }

    function test_EnableController_RevertIfNotOwnerAndNotOperator(
        address alice,
        address bob
    ) public {
        vm.assume(!samePrimaryAccount(alice, bob));

        address vault = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(vault, true);

        vm.prank(alice);
        vm.expectRevert(EulerConductor.NotAuthorized.selector);
        conductor.handlerEnableController(bob, vault);

        vm.prank(bob);
        conductor.setAccountOperator(bob, alice, true);

        vm.prank(alice);
        conductor.handlerEnableController(bob, vault);
    }

    function test_DisableController_RevertIfMsgSenderNotController(
        address alice,
        address bob
    ) public {
        vm.assume(!samePrimaryAccount(alice, bob));

        address vault = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(vault, true);

        vm.assume(alice != vault);

        vm.prank(alice);
        vm.expectRevert(EulerConductor.NotAuthorized.selector);
        conductor.handlerDisableController(bob, vault);

        vm.prank(bob);
        conductor.setAccountOperator(bob, alice, true);

        vm.prank(alice);
        vm.expectRevert(EulerConductor.NotAuthorized.selector); // although operator, controller msg.sender is expected
        conductor.handlerDisableController(bob, vault);

        vm.prank(alice);
        EulerVaultMock(vault).call(
            address(conductor),
            abi.encodeWithSelector(
                EulerConductorHandler.handlerDisableController.selector,
                bob,
                vault
            )
        );
    }

    function test_ControllersManagement_RevertIfVaultNotRegistered(
        address alice
    ) public {
        address vault = address(new EulerVaultMock());

        vm.assume(alice != vault);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                EulerConductor.VaultNotRegistered.selector,
                vault
            )
        );
        conductor.handlerEnableController(alice, vault);

        vm.prank(alice);
        vm.expectRevert(EulerConductor.NotAuthorized.selector);
        conductor.handlerDisableController(alice, vault);

        EulerRegistryMock(registry).setRegistered(vault, true);

        vm.prank(alice);
        conductor.handlerEnableController(alice, vault);

        //EulerVaultMock(vault).reset(); // not necessary as there's no controller to perform the account status check
        vm.prank(alice);
        EulerVaultMock(vault).call(
            address(conductor),
            abi.encodeWithSelector(
                EulerConductorHandler.handlerDisableController.selector,
                alice,
                vault
            )
        );
    }

    function test_ControllersManagement_RevertIfAccountStatusViolated(
        address alice
    ) public {
        address vault = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(vault, true);

        EulerVaultMock(vault).setAccountStatusState(1); // account status is violated

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                EulerConductor.AccountStatusViolation.selector,
                alice
            )
        );
        conductor.handlerEnableController(alice, vault);

        vm.prank(alice);
        // succeeds as there's no controller to perform the account status check
        EulerVaultMock(vault).call(
            address(conductor),
            abi.encodeWithSelector(
                EulerConductorHandler.handlerDisableController.selector,
                alice,
                vault
            )
        );

        EulerVaultMock(vault).reset(); // account status is NOT violated

        vm.prank(alice);
        conductor.handlerEnableCollateral(alice, vault);
    }

    function test_Execute(address alice, uint seed, uint msgValue) public {
        address account;
        if (seed % 2 == 0) {
            // in this case the account is not alice's sub-account thus alice must be an operator
            account = address(uint160(uint160(alice) ^ 256));
            vm.prank(account);
            conductor.setAccountOperator(account, alice, true);
        } else {
            // in this case the account is alice's sub-account
            account = address(uint160(uint160(alice) ^ (seed % 256)));
        }

        address targetContract;
        if (seed % 3 == 0) {
            // test for a non-registered contract
            targetContract = address(new TargetMock());
        } else {
            // test for a registered vault
            targetContract = address(new EulerVaultMock());
            EulerRegistryMock(registry).setRegistered(targetContract, true);

            if (seed % 4 == 0) {
                // test for a enabled controller in order to verify whether account status was checked
                vm.prank(account);
                conductor.enableController(account, targetContract);
                EulerVaultMock(targetContract).reset();
            }
        }

        vm.assume(targetContract != address(conductor));

        bytes memory data = abi.encodeWithSelector(
            TargetMock(targetContract).executeExample.selector,
            address(conductor),
            false,
            Types.EulerBatchItem({
                allowError: false,
                onBehalfOfAccount: account,
                targetContract: targetContract,
                msgValue: msgValue,
                data: abi.encode(0)
            })
        );

        hoax(alice, msgValue);
        conductor.handlerExecute{value: msgValue}(
            targetContract,
            account,
            data
        );
    }

    function test_Execute_RevertIfVaultStatusInvalid(address alice, uint seed) public {
        address targetContract;
        if (seed % 2 == 0) {
            // test for a non-registered contract, in this case vault status is not checked thus doesn't revert
            targetContract = address(new TargetMock());
        } else {
            // test for a registered vault
            targetContract = address(new EulerVaultMock());
            EulerRegistryMock(registry).setRegistered(targetContract, true);
        }

        vm.assume(targetContract != address(conductor));

        bytes memory data = abi.encodeWithSelector(
            TargetMock(targetContract).executeExample.selector,
            address(conductor),
            false,
            Types.EulerBatchItem({
                allowError: false,
                onBehalfOfAccount: alice,
                targetContract: targetContract,
                msgValue: seed,
                data: abi.encode(0)
            })
        );

        hoax(alice, seed);
        conductor.handlerExecute{value: seed}(
            targetContract,
            alice,
            data
        );
    }
}
