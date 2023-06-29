// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/EulerConductor.sol";
import "../src/Types.sol";
import "../src/Set.sol";

contract TargetMock {
    function executeExample(address conductor, address msgSender, uint msgValue, bool checksDeferred, address onBehalfOfAccount) external payable returns (uint) {
        // also tests getExecutionContext() from the conductor
        (bool _checksDeferred, address _onBehalfOfAccount) = EulerConductor(conductor).getExecutionContext();

        require(msg.sender == msgSender, "executeExample/invalid-sender");
        require(msg.value == msgValue, "executeExample/invalid-msg-value");
        require(_checksDeferred == checksDeferred, "executeExample/invalid-checks-deferred");
        require(_onBehalfOfAccount == onBehalfOfAccount, "executeExample/invalid-on-behalf-of-account");

        return msg.value;
    }

    fallback() external {}
}

contract EulerRegistryMock is IEulerVaultRegistry {
    mapping(address => bool) public isRegistered;

    function setRegistered(address vault, bool registered) external {
        isRegistered[vault] = registered;
    }
}

contract EulerVaultMock is IEulerVault, TargetMock, Test {
    bool public hookInitialCallRevert;
    bool public hookFinishCallRevert;
    bool public hookRevertWithStandardError;
    uint internal accountStatusState;
    address[] internal accountStatusChecked;
    bool[] internal hooksCalled;

    constructor() {
        accountStatusState = 0;
        hookInitialCallRevert = false;
        hookFinishCallRevert = false;
        hookRevertWithStandardError = true;
    }

    function setAccountStatusState(uint state) external {
        accountStatusState = state;
    }

    function setInitialCallHookRevert(bool withStandardError) external {
        hookInitialCallRevert = true;
        hookRevertWithStandardError = withStandardError;
    }

    function setFinishCallHookRevert(bool withStandardError) external {
        hookFinishCallRevert = true;
        hookRevertWithStandardError = withStandardError;
    }

    function reset() external {
        accountStatusState = 0;
        hookInitialCallRevert = false;
        hookFinishCallRevert = false;
        hookRevertWithStandardError = true;

        delete accountStatusChecked;
        delete hooksCalled;
    }

    function pushAccountStatusChecked(address account) external {
        accountStatusChecked.push(account);
    }

    function pushHooksCalled(bool initialCall) external {
        hooksCalled.push(initialCall);
    }

    function getAccountStatusChecked() external view returns (address[] memory) {
        return accountStatusChecked;
    }

    function getHooksCalled() external view returns (bool[] memory) {
        return hooksCalled;
    }

    function disableControllerOnConductor(address conductor, address account) public {
        EulerConductor(conductor).disableController(account, address(this));
    }

    function disableController(address account) external override {}

    function checkAccountStatus(address, address[] memory) external view override returns (bool isValid) {
        if (accountStatusState == 0) return true;
        else if (accountStatusState == 1) return false;
        else revert("invalid");
    }

    function vaultStatusHook(bool initialCall, bytes memory data) external view returns (bytes memory result) {
        if (hookInitialCallRevert && initialCall) {
            if (hookRevertWithStandardError) revert VaultStatusHookViolation("hook/initialCall/standard/violation");
            else revert("hook/initialCall/other/violation");
        }

        if (hookFinishCallRevert && !initialCall) {
            if (hookRevertWithStandardError) revert VaultStatusHookViolation("hook/finishCall/standard/violation");
            else revert("hook/finishCall/other/violation");
        }

        if (initialCall) {
            if (abi.decode(data, (uint)) != 0) revert VaultStatusHookViolation("hook/initialCall/input-violation");
        } else {

            if (abi.decode(data, (uint)) != 1) revert VaultStatusHookViolation("hook/finishCall/input-violation");
        }

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
        bool[] hooks;
    }

    using Set for SetStorage;
    SetStorage internal helperSet;

    constructor(address admin, address registry) EulerConductor(admin, registry) {}

    function setChecksDeferredDepth(uint8 depth) external {
        executionContext.checksDeferredDepth = depth;
    }

    function setOnBehalfOfAccount(address account) external {
        executionContext.onBehalfOfAccount = account;
    }

    function requireAccountStatusCheckInternal(address account) internal override {
        super.requireAccountStatusCheckInternal(account);

        address[] memory controllers = accountControllers[account].get();
        if (controllers.length == 1) EulerVaultMock(controllers[0]).pushAccountStatusChecked(account);
    }

    function vaultStatusHookHandler(address vault, bool initialCall, bytes memory data) internal override 
    returns (bytes memory result) {
        result = super.vaultStatusHookHandler(vault, initialCall, data);

        EulerVaultMock(vault).pushHooksCalled(initialCall);
    }

    function verifyStorage(VaultStatusCheck[] memory vsc) internal view {
        require(executionContext.checksDeferredDepth == CHECKS_DEFERRED_DEPTH__INIT, "verifyStorage/checks-deferred");
        require(executionContext.onBehalfOfAccount == address(0), "verifyStorage/checks-deferred");
        require(accountStatusChecks.numElements == 0, "verifyStorage/account-status-checks/numElements");
        require(accountStatusChecks.firstElement == address(0), "verifyStorage/account-status-checks/firstElement");

        for (uint i = 0; i < 10; ++i) {
            require(accountStatusChecks.elements[i] == address(0), "verifyStorage/account-status-checks/elements");
        }

        require(vaultStatusChecks.numElements == 0, "verifyStorage/vault-status-checks/numElements");
        require(vaultStatusChecks.firstElement == address(0), "verifyStorage/vault-status-checks/firstElement");

        for (uint i = 0; i < 10; ++i) {
            require(vaultStatusChecks.elements[i] == address(0), "verifyStorage/vault-status-checks/elements");
        }

        for (uint i = 0; i < vsc.length; ++i) {
            require(vaultStatuses[vsc[i].vault].length == 0, "verifyStorage/vault-statuses");
        }
    }

    function verifyVaultStatusChecks(VaultStatusCheck[] memory vsc) internal view {
        for (uint i = 0; i < vsc.length; ++i) {
            bool[] memory hooks = EulerVaultMock(vsc[i].vault).getHooksCalled();

            require(hooks.length == vsc[i].hooks.length, "verifyVaultStatusChecks/length");

            if (hooks.length == 2) {
                if (hooks[0] == vsc[i].hooks[0]) {
                    require(hooks[1] == vsc[i].hooks[1], "verifyVaultStatusChecks/1=1/hook");
                } else {
                    require(hooks[0] == vsc[i].hooks[1], "verifyVaultStatusChecks/0=1/hook");
                    require(hooks[1] == vsc[i].hooks[0], "verifyVaultStatusChecks/1=0/hook");
                }
            } else if (hooks.length == 1) {
                require(hooks[0] == vsc[i].hooks[0], "verifyVaultStatusChecks/0=0/hook");
            } else {
                revert("unexpected number of hooks called");
            }
        }
    }

    function verifyAccountStatusChecks(AccountStatusCheck[] memory asc) internal {
        for (uint i = 0; i < asc.length; ++i) {
            address[] memory accounts = EulerVaultMock(asc[i].vault).getAccountStatusChecked();

            require(accounts.length == asc[i].accounts.length, "verifyAccountStatusChecks/length");

            // copy the accounts to the helper set
            for (uint j = 0; j < accounts.length; ++j) {
                require(helperSet.insert(accounts[j]), "verifyAccountStatusChecks/add");
            }

            for (uint j = 0; j < asc[i].accounts.length; ++j) {
                require(helperSet.remove(asc[i].accounts[j]), "verifyAccountStatusChecks/remove");
            }
        }
    }

    function collateralControllerChecks(address account) internal {
        if (executionContext.checksDeferredDepth != CHECKS_DEFERRED_DEPTH__INIT) return;

        address[] memory controllers = accountControllers[account].get();

        require(controllers.length <= 1, "collateralControllerChecks/length");

        if (controllers.length == 0) return;

        AccountStatusCheck[] memory asc = new AccountStatusCheck[](1);
        VaultStatusCheck[] memory vsc = new VaultStatusCheck[](0);

        asc[0].vault = controllers[0];
        asc[0].accounts = new address[](1);
        asc[0].accounts[0] = account;

        verifyStorage(vsc);
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

    function handlerBatch(EulerBatchItem[] calldata items, AccountStatusCheck[] memory asc, VaultStatusCheck[] memory vsc) public payable {
        super.batch(items);

        verifyStorage(vsc);
        verifyVaultStatusChecks(vsc);
        verifyAccountStatusChecks(asc);
    }

    function handlerExecute(address targetContract, address onBehalfOfAccount, bytes calldata data) public payable 
    returns (bool success, bytes memory result) {
        (success, result) = super.execute(targetContract, onBehalfOfAccount, data);

        if (executionContext.checksDeferredDepth == CHECKS_DEFERRED_DEPTH__INIT) {
            address[] memory controllers = accountControllers[onBehalfOfAccount].get();
            require(controllers.length <= 1, "handlerExecute/length");

            if (controllers.length == 1) {
                AccountStatusCheck[] memory asc = new AccountStatusCheck[](1);

                asc[0].vault = controllers[0];
                asc[0].accounts = new address[](1);
                asc[0].accounts[0] = onBehalfOfAccount;

                verifyAccountStatusChecks(asc);
            }
        }
        
        if (
            executionContext.checksDeferredDepth == CHECKS_DEFERRED_DEPTH__INIT && 
            EulerRegistryMock(eulerVaultRegistry).isRegistered(targetContract) &&
            !EulerVaultMock(targetContract).hookRevertWithStandardError()
        ) {
            VaultStatusCheck[] memory vsc = new VaultStatusCheck[](1);

            vsc[0].vault = targetContract;
            vsc[0].hooks = new bool[](2);
            vsc[0].hooks[0] = true;
            vsc[0].hooks[1] = false;

            verifyStorage(vsc);
            verifyVaultStatusChecks(vsc);
        } else {
            VaultStatusCheck[] memory vsc = new VaultStatusCheck[](1);
            vsc[0].vault = targetContract;

            verifyStorage(vsc);
        }
    }

    function handlerForward(address targetContract, address onBehalfOfAccount, bytes calldata data) public payable 
    returns (bool success, bytes memory result) {
        (success, result) = super.forward(targetContract, onBehalfOfAccount, data);

        if (executionContext.checksDeferredDepth == CHECKS_DEFERRED_DEPTH__INIT) {
            address[] memory controllers = accountControllers[onBehalfOfAccount].get();
            require(controllers.length <= 1, "handlerExecute/length");

            if (controllers.length == 1) {
                AccountStatusCheck[] memory asc = new AccountStatusCheck[](1);

                asc[0].vault = controllers[0];
                asc[0].accounts = new address[](1);
                asc[0].accounts[0] = onBehalfOfAccount;

                verifyAccountStatusChecks(asc);
            }
        }

        if (
            executionContext.checksDeferredDepth == CHECKS_DEFERRED_DEPTH__INIT && 
            !EulerVaultMock(targetContract).hookRevertWithStandardError()
        ) {
            VaultStatusCheck[] memory vsc = new VaultStatusCheck[](1);

            vsc[0].vault = targetContract;
            vsc[0].hooks = new bool[](2);
            vsc[0].hooks[0] = true;
            vsc[0].hooks[1] = false;

            verifyStorage(vsc);
            verifyVaultStatusChecks(vsc);
        } else {
            VaultStatusCheck[] memory vsc = new VaultStatusCheck[](1);
            vsc[0].vault = targetContract;

            verifyStorage(vsc);
        }
    }
}

contract EulerConductorTest is Test {
    address governor = makeAddr("governor");
    EulerConductorHandler conductor;
    address registry;

    event GovernorAdminSet(address indexed admin);
    event EulerVaultRegistrySet(address indexed registry);
    event AccountOperatorSet(address indexed account, address indexed operator, bool isAuthorized);

    function samePrimaryAccount(address accountOne, address accountTwo) internal pure returns (bool) {
        return (uint160(accountOne) | 0xFF) == (uint160(accountTwo) | 0xFF);
    }

    function setUp() public {
        registry = address(new EulerRegistryMock());
        vm.assume(governor != address(0));
        vm.assume(registry != address(0));
        
        conductor = new EulerConductorHandler(governor, registry);
    }

    function test_SetGovernorAdmin(address newGovernor) public {
        assertEq(conductor.governorAdmin(), governor);

        vm.prank(governor);
        vm.expectEmit(true, false, false, false, address(conductor));
        emit GovernorAdminSet(newGovernor);
        conductor.setGovernorAdmin(newGovernor);

        assertEq(conductor.governorAdmin(), newGovernor);
    }

    function test_SetGovernorAdmin_RevertIfNotGovernor(address newGovernor, address notGovernor) public {
        vm.assume(notGovernor != governor);

        assertEq(conductor.governorAdmin(), governor);

        vm.prank(notGovernor);
        vm.expectRevert(EulerConductor.NotAuthorized.selector);
        conductor.setGovernorAdmin(newGovernor);
    }

    function test_SetEulerVaultRegistry(address newRegistry) public {
        vm.assume(newRegistry != address(0));

        assertEq(conductor.eulerVaultRegistry(), registry);

        vm.prank(governor);
        vm.expectEmit(true, false, false, false, address(conductor));
        emit EulerVaultRegistrySet(newRegistry);
        conductor.setEulerVaultRegistry(newRegistry);

        assertEq(conductor.eulerVaultRegistry(), newRegistry);
    }

    function test_SetEulerVaultRegistry_RevertIfNotGovernor(address newRegistry, address notGovernor) public {
        vm.assume(notGovernor != governor && newRegistry != address(0));

        assertEq(conductor.eulerVaultRegistry(), registry);

        vm.prank(notGovernor);
        vm.expectRevert(EulerConductor.NotAuthorized.selector);
        conductor.setEulerVaultRegistry(newRegistry);
    }

    function test_SetEulerVaultRegistry_RevertIfZeroAddress() public {
        assertEq(conductor.eulerVaultRegistry(), registry);

        vm.prank(governor);
        vm.expectRevert(EulerConductor.InvalidAddress.selector);
        conductor.setEulerVaultRegistry(address(0));
    }

    function test_SetAccountOperator(address alice, address operator) public {
        vm.assume(!samePrimaryAccount(alice, operator));

        for (uint i = 0; i < 256; ++i) {
            address account = address(uint160(uint160(alice) ^ i));

            assertFalse(conductor.accountOperators(account, operator));

            vm.prank(alice);
            vm.expectEmit(true, true, false, true, address(conductor));
            emit AccountOperatorSet(account, operator, true);
            conductor.setAccountOperator(account, operator, true);

            assertTrue(conductor.accountOperators(account, operator));

            vm.prank(alice);
            vm.expectEmit(true, true, false, true, address(conductor));
            emit AccountOperatorSet(account, operator, false);
            conductor.setAccountOperator(account, operator, false);

            assertFalse(conductor.accountOperators(account, operator));
        }
    }

    function test_SetAccountOperator_RevertIfSenderNotAuthorized(address alice, address operator) public {
        vm.assume(!samePrimaryAccount(alice, operator));

        address account = address(uint160(uint160(alice) ^ 256));

        assertFalse(conductor.accountOperators(account, operator));

        vm.prank(alice);
        vm.expectRevert(EulerConductor.NotAuthorized.selector);
        conductor.setAccountOperator(account, operator, true);
    }

    function test_GetExecutionContext(bool deferred, address account) external {
        vm.assume(account != address(0));

        (bool checksDeferred, address onBehalfOfAccount) = conductor.getExecutionContext();

        assertFalse(checksDeferred);
        assertEq(onBehalfOfAccount, address(0));
        
        conductor.setChecksDeferredDepth(deferred ? 2 : 1);
        conductor.setOnBehalfOfAccount(account);

        (checksDeferred, onBehalfOfAccount) = conductor.getExecutionContext();
        
        assertEq(checksDeferred, deferred);
        assertEq(onBehalfOfAccount, account);
    }

    function test_GetExecutionContextExtended(address account, uint seed) external {
        vm.assume(account != address(0));

        address controller = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(controller, true);

        (
            bool checksDeferred, 
            address onBehalfOfAccount, 
            bool controllerEnabled
        ) = conductor.getExecutionContextExtended(account, controller);

        assertFalse(checksDeferred);
        assertEq(onBehalfOfAccount, address(0));
        assertFalse(controllerEnabled);
        
        if (seed % 2 == 0) {
            vm.prank(account);
            conductor.enableController(account, controller);
        }

        conductor.setChecksDeferredDepth(seed % 3 == 0 ? 2 : 1);
        conductor.setOnBehalfOfAccount(account);

        if (seed % 3 == 0) vm.prank(controller);

        (
            checksDeferred, 
            onBehalfOfAccount, 
            controllerEnabled
        ) = conductor.getExecutionContextExtended(account, controller);
        
        assertEq(checksDeferred, seed % 3 == 0 ? true : false);
        assertEq(onBehalfOfAccount, account);
        assertEq(controllerEnabled, seed % 2 == 0 ? true : false);
    }

    function test_GetExecutionContextExtended_RevertIfChecksDeferredAndMsgSenderNotVault(address account) external {
        vm.assume(account != address(0));

        address controller = address(new EulerVaultMock());
        vm.assume(account != address(this));
        
        EulerRegistryMock(registry).setRegistered(controller, true);
        vm.prank(account);
        conductor.enableController(account, controller);
        
        conductor.setChecksDeferredDepth(2);
        conductor.setOnBehalfOfAccount(account);

        vm.expectRevert(EulerConductor.DeferralViolation.selector);
        conductor.getExecutionContextExtended(account, controller);
    }

    function test_SetAccountOperator_RevertIfOperatorIsSenderSubAccount(address alice, uint8 subAccountId) public {
        address operator = address(uint160(uint160(alice) ^ subAccountId));

        assertFalse(conductor.accountOperators(alice, operator));

        vm.prank(alice);
        vm.expectRevert(EulerConductor.InvalidAddress.selector);
        conductor.setAccountOperator(alice, operator, true);
    }

    function test_GetCollaterals(address alice) public {
        conductor.setChecksDeferredDepth(1);
        conductor.getCollaterals(alice);
    }

    function test_GetCollaterals_RevertIfChecksDeferred(address alice) public {
        conductor.setChecksDeferredDepth(2);
        vm.expectRevert(EulerConductor.DeferralViolation.selector);
        conductor.getCollaterals(alice);
    }

    function test_IsCollateralEnabled(address alice, address vault) public {
        conductor.setChecksDeferredDepth(1);
        conductor.isCollateralEnabled(alice, vault);
    }

    function test_IsCollateralEnabled_RevertIfChecksDeferred(
        address alice,
        address vault
    ) public {
        conductor.setChecksDeferredDepth(2);
        vm.expectRevert(EulerConductor.DeferralViolation.selector);
        conductor.isCollateralEnabled(alice, vault);
    }

    function test_CollateralsManagement(address alice, uint8 subAccountId, uint8 numberOfVaults, uint seed) public {
        vm.assume(numberOfVaults <= 10);
        vm.assume(seed > 1000);

        address account = address(uint160(uint160(alice) ^ subAccountId));

        // test collaterals management with use of an operator
        address msgSender = alice;
        if (seed % 2 == 0 && !samePrimaryAccount(account, address(uint160(seed)))) {
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
            address[] memory collateralsPre = conductor.getCollaterals(account);

            address vault = i % 5 == 0
                ? collateralsPre[seed % collateralsPre.length]
                : address(new EulerVaultMock());

            EulerRegistryMock(registry).setRegistered(vault, true);
            bool alreadyEnabled = conductor.isCollateralEnabled(account, vault);

            assert((alreadyEnabled && i % 5 == 0) || (!alreadyEnabled && i % 5 != 0));

            vm.prank(msgSender);
            conductor.handlerEnableCollateral(account, vault);

            address[] memory collateralsPost = conductor.getCollaterals(account);

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
            address[] memory collateralsPre = conductor.getCollaterals(account);
            address vault = collateralsPre[seed % collateralsPre.length];

            vm.prank(msgSender);
            conductor.handlerDisableCollateral(account, vault);

            address[] memory collateralsPost = conductor.getCollaterals(account);

            assertEq(collateralsPost.length, collateralsPre.length - 1);

            for (uint j = 0; j < collateralsPost.length; ++j) {
                assertNotEq(collateralsPost[j], vault);
            }
        }
    }

    function test_CollateralsManagement_RevertIfNotOwnerAndNotOperator(address alice, address bob) public {
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

    function test_CollateralsManagement_RevertIfVaultNotRegistered(address alice) public {
        address vault = address(new EulerVaultMock());

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                EulerConductor.RegistryViolation.selector,
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

    function test_CollateralsManagement_RevertIfAccountStatusViolated(address alice) public {
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
        conductor.setChecksDeferredDepth(1);
        conductor.getControllers(alice);
    }

    function test_GetControllers_RevertIfChecksDeferred(address alice) public {
        conductor.setChecksDeferredDepth(2);
        vm.expectRevert(EulerConductor.DeferralViolation.selector);
        conductor.getControllers(alice);
    }

    function test_IsControllerEnabled(address alice) public {
        address vault = address(new EulerVaultMock());
        conductor.setChecksDeferredDepth(1);
        conductor.isControllerEnabled(alice, vault);

        // even though checks are deferred, the function succeeds if called by the vault asking if vault enabled
        // as a controller
        conductor.setChecksDeferredDepth(1);
        EulerVaultMock(vault).call(
            address(conductor),
            abi.encodeWithSelector(
                EulerConductor.isControllerEnabled.selector,
                alice,
                vault
            )
        );
    }

    function test_IsControllerEnabled_RevertIfChecksDeferredAndMsgSenderNotVault(address alice, address vault) public {
        vm.assume(address(this) != vault);

        conductor.setChecksDeferredDepth(2);
        vm.expectRevert(EulerConductor.DeferralViolation.selector);
        conductor.isControllerEnabled(alice, vault);
    }

    function test_ControllersManagement(address alice, uint8 subAccountId, uint seed) public {
        vm.assume(seed > 1000);

        address account = address(uint160(uint160(alice) ^ subAccountId));

        // test controllers management with use of an operator
        address msgSender = alice;
        if (seed % 2 == 0 && !samePrimaryAccount(account, address(uint160(seed)))) {
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

        // trying to enable second controller will throw on the account status check
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

    function test_EnableController_RevertIfNotOwnerAndNotOperator(address alice, address bob) public {
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

    function test_DisableController_RevertIfMsgSenderNotController(address alice, address bob) public {
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

    function test_ControllersManagement_RevertIfVaultNotRegistered(address alice) public {
        address vault = address(new EulerVaultMock());

        vm.assume(alice != vault);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                EulerConductor.RegistryViolation.selector,
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

    function test_ControllersManagement_RevertIfAccountStatusViolated(address alice) public {
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

    function test_Execute(address alice, uint96 seed) public {
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

        vm.assume(account != address(0));

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
            address(conductor),
            seed,
            false,
            account
        );

        hoax(alice, seed);
        (bool success, bytes memory result) = conductor.handlerExecute{value: seed}(
            targetContract,
            account,
            data
        );

        assertTrue(success);
        assertEq(abi.decode(result, (uint)), seed);

        // should also succeed if the onBehalfOfAccount address passed is 0. it should be replaced with msg.sender
        data = abi.encodeWithSelector(
            TargetMock(targetContract).executeExample.selector,
            address(conductor),
            address(conductor),
            seed,
            false,
            alice
        );

        hoax(alice, seed);
        (success, result) = conductor.handlerExecute{value: seed}(
            targetContract,
            address(0),
            data
        );

        assertTrue(success);
        assertEq(abi.decode(result, (uint)), seed);
    }

    function test_Execute_RevertIfVaultStatusViolated(address alice, uint seed) public {
        vm.assume(alice != address(0));

        address targetContract = address(new EulerVaultMock());
        vm.assume(targetContract != address(conductor));

        if (seed % 2 == 0) {
            // test for a registered vault, in this case vault status is checked thus should revert
            EulerRegistryMock(registry).setRegistered(targetContract, true);
        }

        // test for both hooks reverting with VaultStatusHookViolation error but not both at a time
        if (seed % 4 == 0) {
            EulerVaultMock(targetContract).setInitialCallHookRevert(true);
        } else {
            EulerVaultMock(targetContract).setFinishCallHookRevert(true);
        }

        bytes memory data = abi.encodeWithSelector(
            TargetMock(targetContract).executeExample.selector,
            address(conductor),
            address(conductor),
            seed,
            false,
            alice
        );

        hoax(alice, seed);

        // expect revert only when registered vault
        if (seed % 2 == 0) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    EulerConductor.VaultStatusViolation.selector,
                    targetContract,
                    abi.encodeWithSelector(
                        IEulerVault.VaultStatusHookViolation.selector, 
                        seed % 4 == 0 
                            ? "hook/initialCall/standard/violation"
                            : "hook/finishCall/standard/violation"
                    )
                )
            );
        }

        (bool success, bytes memory result) = conductor.handlerExecute{value: seed}(
            targetContract,
            alice,
            data
        );

        if (seed % 2 == 0) {
            assertFalse(success);
        } else {
            assertTrue(success);
            assertEq(abi.decode(result, (uint)), seed);
        }
    }

    function test_Execute_RevertIfNotOwnerOrOperator(address alice, address bob, uint seed) public {
        vm.assume(!samePrimaryAccount(alice, bob));
        vm.assume(bob != address(0));
        
        address targetContract = address(new EulerVaultMock());
        vm.assume(targetContract != address(conductor));

        EulerRegistryMock(registry).setRegistered(targetContract, true);

        bytes memory data = abi.encodeWithSelector(
            TargetMock(targetContract).executeExample.selector,
            address(conductor),
            address(conductor),
            seed,
            false,
            alice
        );

        hoax(alice, seed);
        vm.expectRevert(EulerConductor.NotAuthorized.selector);
        (bool success,) = conductor.handlerExecute{value: seed}(
            targetContract,
            bob,
            data
        );

        assertFalse(success);
    }

    function test_Execute_RevertIfAccountStatusViolated(address alice, uint seed) public {
        vm.assume(alice != address(0));

        address targetContract = address(new EulerVaultMock());
        vm.assume(targetContract != address(conductor));

        EulerRegistryMock(registry).setRegistered(targetContract, true);

        // the account status will only be checked if a controller is enabled. otherwise it won't revert
        if (seed % 4 != 0) {
            vm.prank(alice);
            conductor.enableController(alice, targetContract);
            EulerVaultMock(targetContract).reset();
        }

        // account status is violated. check both returning false and reverting by the controller
        EulerVaultMock(targetContract).setAccountStatusState(seed % 2 == 0 ? 1 : 2);

        bytes memory data = abi.encodeWithSelector(
            TargetMock(targetContract).executeExample.selector,
            address(conductor),
            address(conductor),
            seed,
            false,
            alice
        );

        hoax(alice, seed);

        if (seed % 4 != 0) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    EulerConductor.AccountStatusViolation.selector,
                    alice
                )
            );
        }

        (bool success, bytes memory result) = conductor.handlerExecute{value: seed}(
            targetContract,
            alice,
            data
        );

        if (seed % 4 == 0) {
            assertTrue(success);
            assertEq(abi.decode(result, (uint)), seed);
        } else {
            assertFalse(success);
        }
    }

    function test_Execute_RevertIfTargetContractInvalid(address alice, uint seed) public {
        vm.assume(alice != address(0));

        // target contract is the conductor
        address targetContract = address(conductor);

        bytes memory data = abi.encodeWithSelector(
            TargetMock(targetContract).executeExample.selector,
            address(conductor),
            targetContract,
            seed,
            false,
            alice
        );

        hoax(alice, seed);
        vm.expectRevert(EulerConductor.InvalidAddress.selector);

        (bool success,) = conductor.handlerExecute{value: seed}(
            targetContract,
            alice,
            data
        );

        assertFalse(success);

        // target contract is the ERC1820 registry
        targetContract = 0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24;
        address dummyTarget = address(new TargetMock());

        vm.etch(targetContract, dummyTarget.code);

        data = abi.encodeWithSelector(
            TargetMock(targetContract).executeExample.selector,
            address(conductor),
            targetContract,
            seed,
            false,
            alice
        );

        hoax(alice, seed);
        vm.expectRevert(EulerConductor.InvalidAddress.selector);

        (success,) = conductor.handlerExecute{value: seed}(
            targetContract,
            alice,
            data
        );

        assertFalse(success);
    }

    function test_Forward(address alice, uint96 seed) public {
        vm.assume(alice != address(0));

        address collateral = address(new EulerVaultMock());
        address controller = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(collateral, true);
        EulerRegistryMock(registry).setRegistered(controller, true);

        vm.prank(alice);
        conductor.enableCollateral(alice, collateral);

        vm.prank(alice);
        conductor.enableController(alice, controller);

        EulerVaultMock(collateral).reset();
        EulerVaultMock(controller).reset();

        bytes memory data = abi.encodeWithSelector(
            TargetMock(collateral).executeExample.selector,
            address(conductor),
            address(conductor),
            seed,
            false,
            alice
        );

        hoax(controller, seed);
        (bool success, bytes memory result) = conductor.handlerForward{value: seed}(
            collateral,
            alice,
            data
        );

        assertTrue(success);
        assertEq(abi.decode(result, (uint)), seed);

        // should also succeed if the onBehalfOfAccount address passed is 0. it should be replaced with msg.sender
        // note that in this case the controller tries to act on behalf itself
        vm.prank(controller);
        conductor.enableCollateral(controller, collateral);

        vm.prank(controller);
        conductor.enableController(controller, controller);

        data = abi.encodeWithSelector(
            TargetMock(collateral).executeExample.selector,
            address(conductor),
            address(conductor),
            seed,
            false,
            controller
        );

        hoax(controller, seed);
        (success, result) = conductor.handlerForward{value: seed}(
            collateral,
            address(0),
            data
        );

        assertTrue(success);
        assertEq(abi.decode(result, (uint)), seed);
    }

    function test_Forward_RevertIfVaultStatusViolated(address alice, uint seed) public {
        vm.assume(alice != address(0));

        address collateral = address(new EulerVaultMock());
        address controller = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(collateral, true);
        EulerRegistryMock(registry).setRegistered(controller, true);

        vm.prank(alice);
        conductor.enableCollateral(alice, collateral);

        vm.prank(alice);
        conductor.enableController(alice, controller);

        EulerVaultMock(collateral).reset();
        EulerVaultMock(controller).reset();

        // test for both hooks reverting with VaultStatusHookViolation error but not both at a time
        if (seed % 2 == 0) {
            EulerVaultMock(collateral).setInitialCallHookRevert(true);
        } else {
            EulerVaultMock(collateral).setFinishCallHookRevert(true);
        }

        bytes memory data = abi.encodeWithSelector(
            TargetMock(collateral).executeExample.selector,
            address(conductor),
            address(conductor),
            seed,
            false,
            alice
        );

        hoax(controller, seed);
        vm.expectRevert(
            abi.encodeWithSelector(
                EulerConductor.VaultStatusViolation.selector,
                collateral,
                abi.encodeWithSelector(
                    IEulerVault.VaultStatusHookViolation.selector, 
                    seed % 2 == 0 
                        ? "hook/initialCall/standard/violation"
                        : "hook/finishCall/standard/violation"
                )
            )
        );
        (bool success,) = conductor.handlerForward{value: seed}(
            collateral,
            alice,
            data
        );

        assertFalse(success);
    }

    function test_Forward_RevertIfAccountStatusViolated(address alice, uint seed) public {
        vm.assume(alice != address(0));

        address collateral = address(new EulerVaultMock());
        address controller = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(collateral, true);
        EulerRegistryMock(registry).setRegistered(controller, true);

        vm.prank(alice);
        conductor.enableCollateral(alice, collateral);

        vm.prank(alice);
        conductor.enableController(alice, controller);

        EulerVaultMock(collateral).reset();
        EulerVaultMock(controller).reset();

        // account status is violated. check both returning false and reverting by the controller
        EulerVaultMock(controller).setAccountStatusState(seed % 2 == 0 ? 1 : 2);

        bytes memory data = abi.encodeWithSelector(
            TargetMock(collateral).executeExample.selector,
            address(conductor),
            address(conductor),
            seed,
            false,
            alice
        );

        hoax(controller, seed);
        vm.expectRevert(
            abi.encodeWithSelector(
                EulerConductor.AccountStatusViolation.selector,
                alice
            )
        );
        (bool success,) = conductor.handlerForward{value: seed}(
            collateral,
            alice,
            data
        );

        assertFalse(success);
    }

    function test_Forward_RevertIfNoControllerEnabled(address alice, uint seed) public {
        vm.assume(alice != address(0));

        address collateral = address(new EulerVaultMock());
        address controller = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(collateral, true);
        EulerRegistryMock(registry).setRegistered(controller, true);

        vm.prank(alice);
        conductor.enableCollateral(alice, collateral);

        EulerVaultMock(collateral).reset();

        bytes memory data = abi.encodeWithSelector(
            TargetMock(collateral).executeExample.selector,
            address(conductor),
            address(conductor),
            seed,
            false,
            alice
        );

        hoax(controller, seed);
        vm.expectRevert(
            abi.encodeWithSelector(
                EulerConductor.ControllerViolation.selector,
                alice
            )
        );
        (bool success,) = conductor.handlerForward{value: seed}(
            collateral,
            alice,
            data
        );

        assertFalse(success);
    }

    function test_Forward_RevertIfMultipleControllersEnabled(address alice, uint seed) public {
        vm.assume(alice != address(0));

        address collateral = address(new EulerVaultMock());
        address controller_1 = address(new EulerVaultMock());
        address controller_2 = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(collateral, true);
        EulerRegistryMock(registry).setRegistered(controller_1, true);
        EulerRegistryMock(registry).setRegistered(controller_2, true);

        // mock checks deferred to enable multiple controllers
        conductor.setChecksDeferredDepth(2);

        vm.prank(alice);
        conductor.enableCollateral(alice, collateral);

        vm.prank(alice);
        conductor.enableController(alice, controller_1);

        vm.prank(alice);
        conductor.enableController(alice, controller_2);

        EulerVaultMock(collateral).reset();
        EulerVaultMock(controller_1).reset();
        EulerVaultMock(controller_2).reset();

        bytes memory data = abi.encodeWithSelector(
            TargetMock(collateral).executeExample.selector,
            address(conductor),
            address(conductor),
            seed,
            false,
            alice
        );

        hoax(controller_1, seed);
        vm.expectRevert(
            abi.encodeWithSelector(
                EulerConductor.ControllerViolation.selector,
                alice
            )
        );
        (bool success,) = conductor.handlerForward{value: seed}(
            collateral,
            alice,
            data
        );

        assertFalse(success);
    }

    function test_Forward_RevertIfMsgSenderIsNotEnabledController(address alice, address randomAddress, uint seed) public {
        vm.assume(alice != address(0));

        address collateral = address(new EulerVaultMock());
        address controller = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(collateral, true);
        EulerRegistryMock(registry).setRegistered(controller, true);

        vm.assume(randomAddress != controller);

        vm.prank(alice);
        conductor.enableCollateral(alice, collateral);

        vm.prank(alice);
        conductor.enableController(alice, controller);

        EulerVaultMock(collateral).reset();
        EulerVaultMock(controller).reset();

        bytes memory data = abi.encodeWithSelector(
            TargetMock(collateral).executeExample.selector,
            address(conductor),
            address(conductor),
            seed,
            false,
            alice
        );

        hoax(randomAddress, seed);
        vm.expectRevert(abi.encodeWithSelector(EulerConductor.NotAuthorized.selector));
        (bool success,) = conductor.handlerForward{value: seed}(
            collateral,
            alice,
            data
        );

        assertFalse(success);
    }

    function test_Forward_RevertIfTargetContractIsNotEnabledCollateral(address alice, address targetContract, uint seed) public {
        vm.assume(alice != address(0));

        address collateral = address(new EulerVaultMock());
        address controller = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(collateral, true);
        EulerRegistryMock(registry).setRegistered(controller, true);

        vm.assume(targetContract != collateral);

        vm.prank(alice);
        conductor.enableCollateral(alice, collateral);

        vm.prank(alice);
        conductor.enableController(alice, controller);

        EulerVaultMock(collateral).reset();
        EulerVaultMock(controller).reset();

        bytes memory data = abi.encodeWithSelector(
            TargetMock(collateral).executeExample.selector,
            address(conductor),
            address(conductor),
            seed,
            false,
            alice
        );

        hoax(controller, seed);
        vm.expectRevert(abi.encodeWithSelector(EulerConductor.NotAuthorized.selector));
        (bool success,) = conductor.handlerForward{value: seed}(
            targetContract,
            alice,
            data
        );

        assertFalse(success);
    }

    function test_CheckAccountsStatus(address[] memory accounts, bool allStatusesValid) external {
        for (uint i = 0; i < accounts.length; i++) {
            address account = accounts[i];

            // avoid duplicate entries in the accounts array not to enable multiple
            // controller for the same account
            bool seen = false;
            for (uint j = 0; j < i; j++) {
                if (accounts[j] == account) {
                    seen = true;
                    break;
                }
            }
            if (seen) continue;

            address controller = address(new EulerVaultMock());
            EulerRegistryMock(registry).setRegistered(controller, true);

            if (!allStatusesValid) {
                vm.prank(account);
                conductor.enableController(account, controller);
                EulerVaultMock(controller).reset();
            }

            // check all the options: account state is ok, account state is violated with
            // controller returning false and reverting
            EulerVaultMock(controller).setAccountStatusState(
                allStatusesValid
                ? 0
                : uint160(account) % 3 == 0
                    ? 0
                    : uint160(account) % 3 == 1
                        ? 1
                        : 2
            );

            if (!(allStatusesValid || uint160(account) % 3 == 0)) {
                assertFalse(conductor.checkAccountStatus(account));
            } else {
                assertTrue(conductor.checkAccountStatus(account));
            }
        }

        bool[] memory isValid = conductor.checkAccountsStatus(accounts);
        for (uint i = 0; i < accounts.length; i++) {
            address account = accounts[i];

            if (!(allStatusesValid || uint160(account) % 3 == 0)) assertFalse(isValid[i]);
            else assertTrue(isValid[i]);
        }
    }

    function test_RequireAccountsStatusCheck(address[] memory accounts, bool allStatusesValid) external {
        for (uint i = 0; i < accounts.length; i++) {
            address account = accounts[i];

            // avoid duplicate entries in the accounts array not to enable multiple
            // controller for the same account
            bool seen = false;
            for (uint j = 0; j < i; j++) {
                if (accounts[j] == account) {
                    seen = true;
                    break;
                }
            }
            if (seen) continue;

            address controller = address(new EulerVaultMock());
            EulerRegistryMock(registry).setRegistered(controller, true);

            if (!allStatusesValid) {
                vm.prank(account);
                conductor.enableController(account, controller);
                EulerVaultMock(controller).reset();
            }

            // check all the options: account state is ok, account state is violated with
            // controller returning false and reverting
            EulerVaultMock(controller).setAccountStatusState(
                allStatusesValid
                ? 0
                : uint160(account) % 3 == 0
                    ? 0
                    : uint160(account) % 3 == 1
                        ? 1
                        : 2
            );

            if (!(allStatusesValid || uint160(account) % 3 == 0)) {
                vm.expectRevert(abi.encodeWithSelector(
                    EulerConductor.AccountStatusViolation.selector,
                    account    
                ));
            }
            conductor.requireAccountStatusCheck(account);
        }

        // check if there's any invalid status expected
        bool anyInvalid = false;
        address invalidAccount;
        for (uint i = 0; i < accounts.length; i++) {
            invalidAccount = accounts[i];
            if (!(allStatusesValid || uint160(invalidAccount) % 3 == 0)) {
                anyInvalid = true;
                break;
            }
        }

        if (anyInvalid) {
            vm.expectRevert(abi.encodeWithSelector(
                EulerConductor.AccountStatusViolation.selector,
                invalidAccount    
            ));
        }
        conductor.requireAccountsStatusCheck(accounts);
    }

    function test_RequireAccountsStatusCheckWhenDeferred(address[] memory accounts) external {
        vm.assume(accounts.length <= 10);
        
        for (uint i = 0; i < accounts.length; i++) {
            address account = accounts[i];

            // avoid duplicate entries in the accounts array not to enable multiple
            // controller for the same account
            bool seen = false;
            for (uint j = 0; j < i; j++) {
                if (accounts[j] == account) {
                    seen = true;
                    break;
                }
            }
            if (seen) continue;

            conductor.setChecksDeferredDepth(1);

            address controller = address(new EulerVaultMock());
            EulerRegistryMock(registry).setRegistered(controller, true);

            vm.prank(account);
            conductor.enableController(account, controller);
            EulerVaultMock(controller).reset();
            EulerVaultMock(controller).setAccountStatusState(2);

            conductor.setChecksDeferredDepth(2);

            // even though the account status state was set to 2 which should revert,
            // it doesn't because in checks deferral we only add the accounts to the set
            // so that the checks can be performed later
            conductor.requireAccountStatusCheck(account);
        }

        conductor.requireAccountsStatusCheck(accounts);
    }

    function test_Batch(address alice, address bob, uint seed) external {
        vm.assume(!samePrimaryAccount(alice, bob));
        vm.assume(seed >= 3);

        Types.EulerBatchItem[] memory items = new Types.EulerBatchItem[](7);
        EulerConductorHandler.AccountStatusCheck[] memory asc = new EulerConductorHandler.AccountStatusCheck[](1);
        EulerConductorHandler.VaultStatusCheck[] memory vsc = new EulerConductorHandler.VaultStatusCheck[](2);

        address controller = address(new EulerVaultMock());
        address otherVault = address(new EulerVaultMock());
        address alicesSubAccount = address(uint160(alice) ^ 0x10);

        EulerRegistryMock(registry).setRegistered(otherVault, true);

        vm.assume(bob != controller);

        // -------------- FIRST BATCH -------------------------
        items[0].allowError = false;
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = registry;
        items[0].msgValue = 0;
        items[0].data = abi.encodeWithSelector(
            EulerRegistryMock.setRegistered.selector,
            controller,
            true
        );

        items[1].allowError = false;
        items[1].onBehalfOfAccount = address(0);
        items[1].targetContract = address(conductor);
        items[1].msgValue = 0;
        items[1].data = abi.encodeWithSelector(
            EulerConductor.enableController.selector,
            alice,
            controller
        );

        items[2].allowError = false;
        items[2].onBehalfOfAccount = alice;
        items[2].targetContract = address(conductor);
        items[2].msgValue = 0;
        items[2].data = abi.encodeWithSelector(
            EulerConductor.setAccountOperator.selector,
            alice,
            bob,
            true
        );

        items[3].allowError = false;
        items[3].onBehalfOfAccount = alicesSubAccount;
        items[3].targetContract = controller;
        items[3].msgValue = 0;
        items[3].data = abi.encodeWithSelector(
            EulerVaultMock.call.selector,
            otherVault,
            ""
        );

        items[4].allowError = false;
        items[4].onBehalfOfAccount = address(0);
        items[4].targetContract = controller;
        items[4].msgValue = seed / 3;
        items[4].data = abi.encodeWithSelector(
            EulerVaultMock.call.selector,
            otherVault,
            abi.encodeWithSelector(
                TargetMock.executeExample.selector,
                address(conductor),
                controller,
                seed / 3,
                true,
                alice
            )
        );

        items[5].allowError = false;
        items[5].onBehalfOfAccount = alice;
        items[5].targetContract = otherVault;
        items[5].msgValue = type(uint).max;
        items[5].data = abi.encodeWithSelector(
            TargetMock.executeExample.selector,
            address(conductor),
            address(conductor),
            seed - seed / 3,
            true,
            alice
        );

        items[6].allowError = false;
        items[6].onBehalfOfAccount = alicesSubAccount;
        items[6].targetContract = address(conductor);
        items[6].msgValue = 0;
        items[6].data = abi.encodeWithSelector(
            EulerConductor.enableController.selector,
            alicesSubAccount,
            controller
        );

        // the following proves that the checks were deferred
        asc[0].vault = controller;
        asc[0].accounts = new address[](2);
        asc[0].accounts[0] = alice;
        asc[0].accounts[1] = alicesSubAccount;

        vsc[0].vault = controller;
        vsc[0].hooks = new bool[](2);
        vsc[0].hooks[0] = true;
        vsc[0].hooks[1] = false;

        vsc[1].vault = otherVault;
        vsc[1].hooks = new bool[](2);
        vsc[1].hooks[0] = true;
        vsc[1].hooks[1] = false;

        hoax(alice, seed);
        conductor.handlerBatch{value: seed}(items, asc, vsc);

        assertTrue(EulerRegistryMock(registry).isRegistered(controller));
        assertTrue(conductor.isControllerEnabled(alice, controller));
        assertTrue(conductor.isControllerEnabled(alicesSubAccount, controller));
        assertTrue(conductor.accountOperators(alice, bob));
        assertEq(address(otherVault).balance, seed);
        EulerVaultMock(controller).reset();

        // -------------- SECOND BATCH -------------------------
        items = new Types.EulerBatchItem[](1);
        asc = new EulerConductorHandler.AccountStatusCheck[](0);
        vsc = new EulerConductorHandler.VaultStatusCheck[](0);

        items[0].allowError = false;
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = address(conductor);
        items[0].msgValue = 0;
        items[0].data= abi.encodeWithSelector(
            EulerConductor.disableController.selector,
            alice,
            controller
        );

        vm.prank(bob);
        vm.expectRevert(EulerConductor.NotAuthorized.selector);
        conductor.handlerBatch(items, asc, vsc);

        // -------------- THIRD BATCH -------------------------
        items = new Types.EulerBatchItem[](1);
        asc = new EulerConductorHandler.AccountStatusCheck[](0);
        vsc = new EulerConductorHandler.VaultStatusCheck[](0);

        items[0].allowError = true;
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = address(conductor);
        items[0].msgValue = 0;
        items[0].data= abi.encodeWithSelector(
            EulerConductor.disableController.selector,
            alice,
            controller
        );

        vm.prank(bob);
        conductor.handlerBatch(items, asc, vsc);

        // the batch had no effect as we allowed error
        assertTrue(conductor.isControllerEnabled(alice, controller));

        // -------------- FOURTH BATCH -------------------------
        items = new Types.EulerBatchItem[](2);
        asc = new EulerConductorHandler.AccountStatusCheck[](0);
        vsc = new EulerConductorHandler.VaultStatusCheck[](1);

        items[0].allowError = true;
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = address(conductor);
        items[0].msgValue = 0;
        items[0].data= abi.encodeWithSelector(
            EulerConductor.disableController.selector,
            alice,
            controller
        );

        items[1].allowError = false;
        items[1].onBehalfOfAccount = alice;
        items[1].targetContract = controller;
        items[1].msgValue = 0;
        items[1].data= abi.encodeWithSelector(
            EulerVaultMock.disableControllerOnConductor.selector,
            address(conductor),
            alice
        );

        vsc[0].vault = controller;
        vsc[0].hooks = new bool[](2);
        vsc[0].hooks[0] = true;
        vsc[0].hooks[1] = false;

        vm.prank(bob);
        conductor.handlerBatch(items, asc, vsc);
        assertFalse(conductor.isControllerEnabled(alice, controller));
    }

    function test_Batch_RevertIfDeferralDepthExceeded(address alice) external {
        Types.EulerBatchItem[] memory items = new Types.EulerBatchItem[](9);

        for (int i = int(items.length - 1); i >= 0; --i) {
            uint j = uint(i);
            items[j].allowError = false;
            items[j].onBehalfOfAccount = alice;
            items[j].targetContract = address(conductor);
            items[j].msgValue = 0;

            if (j == items.length - 1) {
                items[j].data = abi.encodeWithSelector(
                    EulerConductor.batch.selector,
                    new Types.EulerBatchItem[](0)
                );
            } else {
                Types.EulerBatchItem[] memory nestedItems = new Types.EulerBatchItem[](1);
                nestedItems[0] = items[j+1];

                items[j].data = abi.encodeWithSelector(
                    EulerConductor.batch.selector,
                    nestedItems
                );
            }
        }

        vm.prank(alice);
        vm.expectRevert(EulerConductor.DeferralViolation.selector);
        (bool success, ) = address(conductor).call(abi.encodeWithSelector(
            EulerConductor.batch.selector,
            items
        ));

        assertTrue(success); // is true because of vm.expectRevert() above
    }

    function test_BatchRevert_AND_BatchSimulation(address alice) external {
        Types.EulerBatchItem[] memory items = new Types.EulerBatchItem[](1);
        Types.EulerResult[] memory expectedBatchItemsResult = new Types.EulerResult[](1);
        Types.EulerResult[] memory expectedAccountsStatusResult = new Types.EulerResult[](1);
        Types.EulerResult[] memory expectedVaultsStatusResult = new Types.EulerResult[](1);

        address controller = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(controller, true);

        vm.prank(alice);
        conductor.enableController(alice, controller);

        items[0].allowError = false;
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = controller;
        items[0].msgValue = 0;
        items[0].data = "";

        expectedBatchItemsResult[0].success = true;
        expectedBatchItemsResult[0].result = "";

        expectedAccountsStatusResult[0].success = true;
        expectedAccountsStatusResult[0].result = "";

        expectedVaultsStatusResult[0].success = true;
        expectedVaultsStatusResult[0].result = abi.encode(2);

        // regular batch doesn't revert
        vm.prank(alice);
        conductor.batch(items);

        {
            vm.prank(alice);
            try conductor.batchRevert(items) {
                assertTrue(false);
            } catch (bytes memory err) {
                assertEq(bytes4(err), EulerConductor.RevertedBatchResult.selector);

                assembly { err := add(err, 4) }
                (
                    Types.EulerResult[] memory batchItemsResult,
                    Types.EulerResult[] memory accountsStatusResult,
                    Types.EulerResult[] memory vaultsStatusResult 
                ) = abi.decode(err, (Types.EulerResult[], Types.EulerResult[], Types.EulerResult[]));
                
                assertEq(expectedBatchItemsResult.length, batchItemsResult.length);
                assertEq(expectedBatchItemsResult[0].success, batchItemsResult[0].success);
                assertEq(keccak256(expectedBatchItemsResult[0].result), keccak256(batchItemsResult[0].result));

                assertEq(expectedAccountsStatusResult.length, accountsStatusResult.length);
                assertEq(expectedAccountsStatusResult[0].success, accountsStatusResult[0].success);
                assertEq(keccak256(expectedAccountsStatusResult[0].result), keccak256(accountsStatusResult[0].result));

                assertEq(expectedVaultsStatusResult.length, vaultsStatusResult.length);
                assertEq(expectedVaultsStatusResult[0].success, vaultsStatusResult[0].success);
                assertEq(keccak256(expectedVaultsStatusResult[0].result), keccak256(vaultsStatusResult[0].result));
            }
        }

        {
            EulerVaultMock(controller).reset();
            vm.prank(alice);
            (
                Types.EulerResult[] memory batchItemsResult,
                Types.EulerResult[] memory accountsStatusResult,
                Types.EulerResult[] memory vaultsStatusResult 
            ) = conductor.batchSimulation(items);

            assertEq(expectedBatchItemsResult.length, batchItemsResult.length);
            assertEq(expectedBatchItemsResult[0].success, batchItemsResult[0].success);
            assertEq(keccak256(expectedBatchItemsResult[0].result), keccak256(batchItemsResult[0].result));

            assertEq(expectedAccountsStatusResult.length, accountsStatusResult.length);
            assertEq(expectedAccountsStatusResult[0].success, accountsStatusResult[0].success);
            assertEq(keccak256(expectedAccountsStatusResult[0].result), keccak256(accountsStatusResult[0].result));

            assertEq(expectedVaultsStatusResult.length, vaultsStatusResult.length);
            assertEq(expectedVaultsStatusResult[0].success, vaultsStatusResult[0].success);
            assertEq(keccak256(expectedVaultsStatusResult[0].result), keccak256(vaultsStatusResult[0].result));
        }
    }
}
