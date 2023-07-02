// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/EulerConductor.sol";
import "../src/Types.sol";
import "../src/Set.sol";

contract TargetMock {
    function func(address conductor, address msgSender, uint msgValue, bool checksDeferred, address onBehalfOfAccount) external payable returns (uint) {
        // also tests getExecutionContext() from the conductor
        (bool _checksDeferred, address _onBehalfOfAccount) = EulerConductor(conductor).getExecutionContext();

        require(msg.sender == msgSender, "func/invalid-sender");
        require(msg.value == msgValue, "func/invalid-msg-value");
        require(_checksDeferred == checksDeferred, "func/invalid-checks-deferred");
        require(_onBehalfOfAccount == onBehalfOfAccount, "func/invalid-on-behalf-of-account");

        return msg.value;
    }
}

contract EulerRegistryMock is IEulerVaultRegistry {
    mapping(address => bool) public isRegistered;

    function setRegistered(address vault, bool registered) external {
        isRegistered[vault] = registered;
    }
}

contract EulerVaultMock is IEulerVault, TargetMock, Test {
    address public immutable eulerConductor;
    uint internal vaultStatusState;
    bool[] internal vaultStatusChecked;
    uint internal accountStatusState;
    address[] internal accountStatusChecked;

    constructor(address _eulerConductor) {
        eulerConductor = _eulerConductor;
    }

    function setVaultStatusState(uint state) external {
        vaultStatusState = state;
    }

    function setAccountStatusState(uint state) external {
        accountStatusState = state;
    }

    function reset() external {
        vaultStatusState = 0;
        accountStatusState = 0;
        delete vaultStatusChecked;
        delete accountStatusChecked;
    }

    function pushVaultStatusChecked() external {
        vaultStatusChecked.push(true);
    }

    function pushAccountStatusChecked(address account) external {
        accountStatusChecked.push(account);
    }

    function getVaultStatusChecked() external view returns (bool[] memory) {
        return vaultStatusChecked;
    }

    function getAccountStatusChecked() external view returns (address[] memory) {
        return accountStatusChecked;
    }

    function disableController(address account) external override {
        EulerConductor(eulerConductor).disableController(account, address(this));
    }

    function checkVaultStatus() external view override 
    returns (bool isValid, bytes memory data) {
        if (vaultStatusState == 0) return (true, "");
        else if (vaultStatusState == 1) return (false, "vault status violation");
        else revert("invalid");
    }

    function checkAccountStatus(address, address[] memory) external view override 
    returns (bool isValid, bytes memory data) {
        if (accountStatusState == 0) return (true, "");
        else if (accountStatusState == 1) return (false, "account status violation");
        else revert("invalid");
    }

    function requireChecks(address account) external payable {
        EulerConductor(eulerConductor).requireAccountStatusCheck(account);
        EulerConductor(eulerConductor).requireVaultStatusCheck(address(this));
    }

    function call(address target, bytes memory data) external payable {
        (bool success, ) = target.call{value: msg.value}(data);
        require(success, "call/failed");
    }
}

contract EulerVaultMaliciousMock is IEulerVault {
    address public immutable eulerConductor;

    constructor(address _eulerConductor) {
        eulerConductor = _eulerConductor;
    }

    function disableController(address account) external override {}

    function checkVaultStatus() external override returns (bool, bytes memory) {
        // try to reenter the conductor batch. if it were possible, one could defer other vaults status checks
        // by entering a batch here and make the checkStatusAll() malfunction. possible attack:
        // - execute a batch with any item that calls checkVaultStatus() on vault A
        // - checkStatusAll() calls checkVaultStatus() on vault A
        // - vault A reenters a batch with any item that calls checkVaultStatus() on vault B
        // - because checks are deferred, checkVaultStatus() on vault B is not executed right away
        // - control is handed over back to checkStatusAll() which had numElements = 1 when entering the loop
        // - the loop ends and "delete vaultStatusChecks" is called removing the vault status check scheduled on vault B
        Types.EulerBatchItem[] memory items = new Types.EulerBatchItem[](1);
        items[0].allowError = false;
        items[0].onBehalfOfAccount = address(0);
        items[0].targetContract = address(0);
        items[0].msgValue = 0;
        items[0].data = "";

        try EulerConductor(eulerConductor).batch(items) {
            assert(false);
        } catch (bytes memory err) {
            assert(bytes4(err) == EulerConductor.ChecksReentrancy.selector);
            return (false, "");
        }
        return (true, "");
    }

    function checkAccountStatus(address, address[] memory) external pure override 
    returns (bool isValid, bytes memory data) {
        return (true, "");
    }

    function requireChecks(address account) external payable {
        EulerConductor(eulerConductor).requireAccountStatusCheck(account);
        EulerConductor(eulerConductor).requireVaultStatusCheck(address(this));
    }
}

contract EulerConductorHandler is EulerConductor {
    address[] expectedAccountsChecked;
    address[] expectedVaultsChecked;

    using Set for SetStorage;

    constructor(address admin, address registry) EulerConductor(admin, registry) {}

    function reset() external {
        delete expectedAccountsChecked;
        delete expectedVaultsChecked;
    }

    function setBatchDepth(uint8 depth) external {
        executionContext.batchDepth = depth;
    }

    function setChecksInProgressLock(bool locked) external {
        executionContext.checksInProgressLock = locked;
    }

    function setOnBehalfOfAccount(address account) external {
        executionContext.onBehalfOfAccount = account;
    }

    function pushIntoExpectedAccountsChecked(address account) external {
        expectedAccountsChecked.push(account);
    }

    function pushIntoExpectedVaultsChecked(address vault) external {
        expectedVaultsChecked.push(vault);
    }

    function requireAccountStatusCheck(address account) public override {
        super.requireAccountStatusCheck(account);

        expectedAccountsChecked.push(account);
    }

    function requireAccountStatusCheckInternal(address account) internal override {
        super.requireAccountStatusCheckInternal(account);

        address[] memory controllers = accountControllers[account].get();
        if (controllers.length == 1) EulerVaultMock(controllers[0]).pushAccountStatusChecked(account);
    }

    function requireVaultStatusCheck(address vault) public override {
        super.requireVaultStatusCheck(vault);

        expectedVaultsChecked.push(vault);
    }

    function requireVaultStatusCheckInternal(address vault) internal override {
        super.requireVaultStatusCheckInternal(vault);

        EulerVaultMock(vault).pushVaultStatusChecked();
    }

    function verifyStorage() internal view {
        require(executionContext.batchDepth == BATCH_DEPTH__INIT, "verifyStorage/checks-deferred");
        require(executionContext.checksInProgressLock == false, "verifyStorage/checks-in-progress-lock");
        require(executionContext.onBehalfOfAccount == address(0), "verifyStorage/on-behalf-of-account");
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
    }

    function verifyVaultStatusChecks() internal view {
        for (uint i = 0; i < expectedVaultsChecked.length; ++i) {
            require(EulerVaultMock(expectedVaultsChecked[i]).getVaultStatusChecked().length == 1, "verifyVaultStatusChecks");
        }
    }

    function verifyAccountStatusChecks() internal view {
        for (uint i = 0; i < expectedAccountsChecked.length; ++i) {
            address[] memory controllers = accountControllers[expectedAccountsChecked[i]].get();

            require(controllers.length <= 1, "verifyAccountStatusChecks/length");

            if (controllers.length == 0) continue;

            address[] memory accounts = EulerVaultMock(controllers[0]).getAccountStatusChecked();

            uint counter = 0;
            for(uint j = 0; j < accounts.length; ++j) {
                if (accounts[j] == expectedAccountsChecked[i]) counter++;
            }

            require(counter == 1, "verifyAccountStatusChecks/counter");
        }
    }

    function handlerEnableCollateral(address account, address vault) external {
        super.enableCollateral(account, vault);

        if (executionContext.batchDepth != BATCH_DEPTH__INIT) return;

        expectedAccountsChecked.push(account);
        verifyStorage();
        verifyAccountStatusChecks();
    }

    function handlerDisableCollateral(address account, address vault) external {
        super.disableCollateral(account, vault);

        if (executionContext.batchDepth != BATCH_DEPTH__INIT) return;

        expectedAccountsChecked.push(account);
        verifyStorage();
        verifyAccountStatusChecks();
    }

    function handlerEnableController(address account, address vault) external {
        super.enableController(account, vault);

        if (executionContext.batchDepth != BATCH_DEPTH__INIT) return;

        expectedAccountsChecked.push(account == address(0) ? msg.sender : account);
        verifyStorage();
        verifyAccountStatusChecks();
    }

    function handlerDisableController(address account, address vault) external {
        super.disableController(account, vault);

        if (executionContext.batchDepth != BATCH_DEPTH__INIT) return;

        expectedAccountsChecked.push(account == address(0) ? msg.sender : account);
        verifyStorage();
        verifyAccountStatusChecks();
    }

    function handlerBatch(EulerBatchItem[] calldata items) public payable {
        super.batch(items);

        if (executionContext.batchDepth != BATCH_DEPTH__INIT) return;

        verifyStorage();
        verifyVaultStatusChecks();
        verifyAccountStatusChecks();
    }

    function handlerCall(address targetContract, address onBehalfOfAccount, bytes calldata data) public payable 
    returns (bool success, bytes memory result) {
        (success, result) = super.call(targetContract, onBehalfOfAccount, data);

        verifyStorage();
        verifyVaultStatusChecks();
        verifyAccountStatusChecks();
    }

    function handlerCallFromControllerToCollateral(address targetContract, address onBehalfOfAccount, bytes calldata data) public payable 
    returns (bool success, bytes memory result) {
        (success, result) = super.callFromControllerToCollateral(targetContract, onBehalfOfAccount, data);

        verifyStorage();
        verifyVaultStatusChecks();
        verifyAccountStatusChecks();
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

    function test_SetAccountOperator_RevertIfOperatorIsSenderSubAccount(address alice, uint8 subAccountId) public {
        address operator = address(uint160(uint160(alice) ^ subAccountId));

        assertFalse(conductor.accountOperators(alice, operator));

        vm.prank(alice);
        vm.expectRevert(EulerConductor.InvalidAddress.selector);
        conductor.setAccountOperator(alice, operator, true);
    }

    function test_GetExecutionContext(uint8 depth, address account) external {
        vm.assume(depth > 0);
        vm.assume(account != address(0));

        (bool checksDeferred, address onBehalfOfAccount) = conductor.getExecutionContext();

        assertFalse(checksDeferred);
        assertEq(onBehalfOfAccount, address(0));
        
        conductor.setBatchDepth(depth);
        conductor.setOnBehalfOfAccount(account);

        (checksDeferred, onBehalfOfAccount) = conductor.getExecutionContext();
        
        assertEq(checksDeferred, depth > 1 ? true : false);
        assertEq(onBehalfOfAccount, account);
    }

    function test_GetExecutionContextExtended(address account, uint seed) external {
        vm.assume(account != address(0));

        address controller = address(new EulerVaultMock(address(conductor)));
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

        conductor.setBatchDepth(seed % 3 == 0 ? 2 : 1);
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

        address controller = address(new EulerVaultMock(address(conductor)));
        vm.assume(account != address(this));
        vm.assume(account != controller);
        
        EulerRegistryMock(registry).setRegistered(controller, true);
        vm.prank(account);
        conductor.enableController(account, controller);
        
        conductor.setBatchDepth(2);
        conductor.setOnBehalfOfAccount(account);

        vm.prank(account);
        vm.expectRevert(EulerConductor.DeferralViolation.selector);
        conductor.getExecutionContextExtended(account, controller);
    }

    function test_GetCollaterals(address alice) public {
        conductor.setBatchDepth(1);
        conductor.getCollaterals(alice);
    }

    function test_GetCollaterals_RevertIfChecksDeferred(address alice) public {
        conductor.setBatchDepth(2);
        vm.expectRevert(EulerConductor.DeferralViolation.selector);
        conductor.getCollaterals(alice);
    }

    function test_IsCollateralEnabled(address alice, address vault) public {
        conductor.setBatchDepth(1);
        conductor.isCollateralEnabled(alice, vault);
    }

    function test_IsCollateralEnabled_RevertIfChecksDeferred(address alice, address vault) public {
        conductor.setBatchDepth(2);
        vm.expectRevert(EulerConductor.DeferralViolation.selector);
        conductor.isCollateralEnabled(alice, vault);
    }

    function test_CollateralsManagement(address alice, uint8 subAccountId, uint8 numberOfVaults, uint seed) public {
        vm.assume(numberOfVaults > 0 && numberOfVaults <= 10);
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
        address controller = address(new EulerVaultMock(address(conductor)));
        if (seed % 3 == 0) {
            EulerRegistryMock(registry).setRegistered(controller, true);

            vm.prank(alice);
            conductor.enableController(account, controller);
        }

        // enabling collaterals
        for (uint i = 1; i <= numberOfVaults; ++i) {
            conductor.reset();
            EulerVaultMock(controller).reset();
            address[] memory collateralsPre = conductor.getCollaterals(account);

            address vault = i % 5 == 0
                ? collateralsPre[seed % collateralsPre.length]
                : address(new EulerVaultMock(address(conductor)));

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
            conductor.reset();
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

        address vault = address(new EulerVaultMock(address(conductor)));
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
        address vault = address(new EulerVaultMock(address(conductor)));

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
        address vault = address(new EulerVaultMock(address(conductor)));
        EulerRegistryMock(registry).setRegistered(vault, true);

        address controller = address(new EulerVaultMock(address(conductor)));
        EulerRegistryMock(registry).setRegistered(controller, true);

        vm.prank(alice);
        conductor.enableController(alice, controller);
        EulerVaultMock(controller).reset();

        EulerVaultMock(controller).setAccountStatusState(1); // account status is violated

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                EulerConductor.AccountStatusViolation.selector,
                alice,
                "account status violation"
            )
        );
        conductor.handlerEnableCollateral(alice, vault);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                EulerConductor.AccountStatusViolation.selector,
                alice,
                "account status violation"
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
        conductor.setBatchDepth(1);
        conductor.getControllers(alice);
    }

    function test_GetControllers_RevertIfChecksDeferred(address alice) public {
        conductor.setBatchDepth(2);
        vm.expectRevert(EulerConductor.DeferralViolation.selector);
        conductor.getControllers(alice);
    }

    function test_IsControllerEnabled(address alice) public {
        address vault = address(new EulerVaultMock(address(conductor)));
        conductor.setBatchDepth(1);
        conductor.isControllerEnabled(alice, vault);

        // even though checks are deferred, the function succeeds if called by the vault asking if vault enabled
        // as a controller
        conductor.setBatchDepth(2);
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
        vm.assume(alice != vault);
        vm.assume(address(this) != vault);

        conductor.setBatchDepth(2);

        vm.prank(alice);
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
        address vault = address(new EulerVaultMock(address(conductor)));
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
        conductor.reset();
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
        address otherVault = address(new EulerVaultMock(address(conductor)));
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
        conductor.reset();
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

        address vault = address(new EulerVaultMock(address(conductor)));
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

        address vault = address(new EulerVaultMock(address(conductor)));
        EulerRegistryMock(registry).setRegistered(vault, true);

        vm.assume(alice != vault);

        vm.prank(alice);
        vm.expectRevert(EulerConductor.NotAuthorized.selector);
        conductor.handlerDisableController(bob, vault);

        vm.prank(bob);
        conductor.setAccountOperator(bob, alice, true);

        vm.prank(alice);
        vm.expectRevert(EulerConductor.NotAuthorized.selector); // although operator, controller msg.sender is still expected
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
        address vault = address(new EulerVaultMock(address(conductor)));

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

        conductor.reset();
        EulerVaultMock(vault).reset();
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
        address vault = address(new EulerVaultMock(address(conductor)));
        EulerRegistryMock(registry).setRegistered(vault, true);

        EulerVaultMock(vault).setAccountStatusState(1); // account status is violated

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                EulerConductor.AccountStatusViolation.selector,
                alice,
                "account status violation"
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

        conductor.reset();
        EulerVaultMock(vault).reset();
        EulerVaultMock(vault).setAccountStatusState(1); // account status is still violated

        vm.prank(alice);
        // succeeds as there's no controller to perform the account status check
        conductor.handlerEnableCollateral(alice, vault);

        conductor.reset();
        EulerVaultMock(vault).reset(); // account status is no longer violated in order to enable controller

        vm.prank(alice);
        conductor.handlerEnableController(alice, vault);

        conductor.reset();
        EulerVaultMock(vault).reset();
        EulerVaultMock(vault).setAccountStatusState(1); // account status is violated again

        vm.prank(alice);
        // it won't succeed as this time we have a controller so the account status check is performed
        vm.expectRevert(
            abi.encodeWithSelector(
                EulerConductor.AccountStatusViolation.selector,
                alice,
                "account status violation"
            )
        );
        conductor.handlerEnableCollateral(alice, vault);
    }

    function test_Call(address alice, uint96 seed) public {
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

        address targetContract = address(new TargetMock());
        vm.assume(targetContract != address(conductor));

        bytes memory data = abi.encodeWithSelector(
            TargetMock(targetContract).func.selector,
            address(conductor),
            address(conductor),
            seed,
            false,
            account
        );

        hoax(alice, seed);
        (bool success, bytes memory result) = conductor.handlerCall{value: seed}(
            targetContract,
            account,
            data
        );

        assertTrue(success);
        assertEq(abi.decode(result, (uint)), seed);

        // should also succeed if the onBehalfOfAccount address passed is 0. it should be replaced with msg.sender
        data = abi.encodeWithSelector(
            TargetMock(targetContract).func.selector,
            address(conductor),
            address(conductor),
            seed,
            false,
            alice
        );

        hoax(alice, seed);
        (success, result) = conductor.handlerCall{value: seed}(
            targetContract,
            address(0),
            data
        );

        assertTrue(success);
        assertEq(abi.decode(result, (uint)), seed);
    }


    function test_Call_RevertIfNotOwnerOrOperator(address alice, address bob, uint seed) public {
        vm.assume(!samePrimaryAccount(alice, bob));
        vm.assume(bob != address(0));
        
        address targetContract = address(new TargetMock());
        vm.assume(targetContract != address(conductor));

        bytes memory data = abi.encodeWithSelector(
            TargetMock(targetContract).func.selector,
            address(conductor),
            address(conductor),
            seed,
            false,
            alice
        );

        hoax(alice, seed);
        vm.expectRevert(EulerConductor.NotAuthorized.selector);
        (bool success,) = conductor.handlerCall{value: seed}(
            targetContract,
            bob,
            data
        );

        assertFalse(success);
    }


    function test_Call_RevertIfTargetContractInvalid(address alice, uint seed) public {
        vm.assume(alice != address(0));

        // target contract is the conductor
        address targetContract = address(conductor);

        bytes memory data = abi.encodeWithSelector(
            TargetMock(targetContract).func.selector,
            address(conductor),
            targetContract,
            seed,
            false,
            alice
        );

        hoax(alice, seed);
        vm.expectRevert(EulerConductor.InvalidAddress.selector);

        (bool success,) = conductor.handlerCall{value: seed}(
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
            TargetMock(targetContract).func.selector,
            address(conductor),
            targetContract,
            seed,
            false,
            alice
        );

        hoax(alice, seed);
        vm.expectRevert(EulerConductor.InvalidAddress.selector);

        (success,) = conductor.handlerCall{value: seed}(
            targetContract,
            alice,
            data
        );

        assertFalse(success);
    }

    function test_CallFromControllerToCollateral(address alice, uint96 seed) public {
        vm.assume(alice != address(0));

        address collateral = address(new EulerVaultMock(address(conductor)));
        address controller = address(new EulerVaultMock(address(conductor)));
        EulerRegistryMock(registry).setRegistered(collateral, true);
        EulerRegistryMock(registry).setRegistered(controller, true);

        vm.prank(alice);
        conductor.enableCollateral(alice, collateral);

        vm.prank(alice);
        conductor.enableController(alice, controller);

        bytes memory data = abi.encodeWithSelector(
            TargetMock(collateral).func.selector,
            address(conductor),
            address(conductor),
            seed,
            false,
            alice
        );

        hoax(controller, seed);
        (bool success, bytes memory result) = conductor.handlerCallFromControllerToCollateral{value: seed}(
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
            TargetMock(collateral).func.selector,
            address(conductor),
            address(conductor),
            seed,
            false,
            controller
        );

        hoax(controller, seed);
        (success, result) = conductor.handlerCallFromControllerToCollateral{value: seed}(
            collateral,
            address(0),
            data
        );

        assertTrue(success);
        assertEq(abi.decode(result, (uint)), seed);
    }

    function test_CallFromControllerToCollateral_RevertIfNoControllerEnabled(address alice, uint seed) public {
        vm.assume(alice != address(0));

        address collateral = address(new EulerVaultMock(address(conductor)));
        address controller = address(new EulerVaultMock(address(conductor)));
        EulerRegistryMock(registry).setRegistered(collateral, true);
        EulerRegistryMock(registry).setRegistered(controller, true);

        vm.prank(alice);
        conductor.enableCollateral(alice, collateral);

        bytes memory data = abi.encodeWithSelector(
            TargetMock(collateral).func.selector,
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
        (bool success,) = conductor.handlerCallFromControllerToCollateral{value: seed}(
            collateral,
            alice,
            data
        );

        assertFalse(success);
    }

    function test_CallFromControllerToCollateral_RevertIfMultipleControllersEnabled(address alice, uint seed) public {
        vm.assume(alice != address(0));

        address collateral = address(new EulerVaultMock(address(conductor)));
        address controller_1 = address(new EulerVaultMock(address(conductor)));
        address controller_2 = address(new EulerVaultMock(address(conductor)));
        EulerRegistryMock(registry).setRegistered(collateral, true);
        EulerRegistryMock(registry).setRegistered(controller_1, true);
        EulerRegistryMock(registry).setRegistered(controller_2, true);

        // mock checks deferred to enable multiple controllers
        conductor.setBatchDepth(2);

        vm.prank(alice);
        conductor.enableCollateral(alice, collateral);

        vm.prank(alice);
        conductor.enableController(alice, controller_1);

        vm.prank(alice);
        conductor.enableController(alice, controller_2);

        bytes memory data = abi.encodeWithSelector(
            TargetMock(collateral).func.selector,
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
        (bool success,) = conductor.handlerCallFromControllerToCollateral{value: seed}(
            collateral,
            alice,
            data
        );

        assertFalse(success);
    }

    function test_CallFromControllerToCollateral_RevertIfMsgSenderIsNotEnabledController(address alice, address randomAddress, uint seed) public {
        vm.assume(alice != address(0));

        address collateral = address(new EulerVaultMock(address(conductor)));
        address controller = address(new EulerVaultMock(address(conductor)));
        EulerRegistryMock(registry).setRegistered(collateral, true);
        EulerRegistryMock(registry).setRegistered(controller, true);

        vm.assume(randomAddress != controller);

        vm.prank(alice);
        conductor.enableCollateral(alice, collateral);

        vm.prank(alice);
        conductor.enableController(alice, controller);

        bytes memory data = abi.encodeWithSelector(
            TargetMock(collateral).func.selector,
            address(conductor),
            address(conductor),
            seed,
            false,
            alice
        );

        hoax(randomAddress, seed);
        vm.expectRevert(abi.encodeWithSelector(EulerConductor.NotAuthorized.selector));
        (bool success,) = conductor.handlerCallFromControllerToCollateral{value: seed}(
            collateral,
            alice,
            data
        );

        assertFalse(success);
    }

    function test_CallFromControllerToCollateral_RevertIfTargetContractIsNotEnabledCollateral(address alice, address targetContract, uint seed) public {
        vm.assume(alice != address(0));

        address collateral = address(new EulerVaultMock(address(conductor)));
        address controller = address(new EulerVaultMock(address(conductor)));
        EulerRegistryMock(registry).setRegistered(collateral, true);
        EulerRegistryMock(registry).setRegistered(controller, true);

        vm.assume(targetContract != collateral);

        vm.prank(alice);
        conductor.enableCollateral(alice, collateral);

        vm.prank(alice);
        conductor.enableController(alice, controller);

        bytes memory data = abi.encodeWithSelector(
            TargetMock(collateral).func.selector,
            address(conductor),
            address(conductor),
            seed,
            false,
            alice
        );

        hoax(controller, seed);
        vm.expectRevert(abi.encodeWithSelector(EulerConductor.NotAuthorized.selector));
        (bool success,) = conductor.handlerCallFromControllerToCollateral{value: seed}(
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

            address controller = address(new EulerVaultMock(address(conductor)));
            EulerRegistryMock(registry).setRegistered(controller, true);

            if (!allStatusesValid) {
                vm.prank(account);
                conductor.enableController(account, controller);
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

            address controller = address(new EulerVaultMock(address(conductor)));
            EulerRegistryMock(registry).setRegistered(controller, true);

            if (!allStatusesValid) {
                vm.prank(account);
                conductor.enableController(account, controller);
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
                    account,
                    uint160(account) % 3 == 1
                        ? "account status violation"
                        : ""
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
                invalidAccount,
                uint160(invalidAccount) % 3 == 1
                    ? "account status violation"
                    : ""
            ));
        }
        conductor.requireAccountsStatusCheck(accounts);
    }

    function test_RequireAccountsStatusCheckWhenDeferred(address[] memory accounts) external {
        vm.assume(accounts.length > 0 && accounts.length <= 10);
        
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

            conductor.setBatchDepth(1);

            address controller = address(new EulerVaultMock(address(conductor)));
            EulerRegistryMock(registry).setRegistered(controller, true);

            vm.prank(account);
            conductor.enableController(account, controller);
            EulerVaultMock(controller).setAccountStatusState(1);

            conductor.setBatchDepth(2);

            // even though the account status state was set to 1 which should revert,
            // it doesn't because in checks deferral we only add the accounts to the set
            // so that the checks can be performed later
            conductor.requireAccountStatusCheck(account);
        }

        conductor.requireAccountsStatusCheck(accounts);

        // checks no longer deferred
        conductor.setBatchDepth(1);

        vm.expectRevert(abi.encodeWithSelector(
            EulerConductor.AccountStatusViolation.selector,
            accounts[0],
            "account status violation"
        ));
        conductor.requireAccountsStatusCheck(accounts);
    }

    function test_RequireVaultStatusCheck(uint8 vaultsNumber, bool allStatusesValid) external {
        vm.assume(vaultsNumber > 0 && vaultsNumber <= 10);
        
        for (uint i = 0; i < vaultsNumber; i++) {
            address vault = address(new EulerVaultMock(address(conductor)));

            // check all the options: vault state is ok, vault state is violated with
            // controller returning false and reverting
            EulerVaultMock(vault).setVaultStatusState(
                allStatusesValid
                ? 0
                : uint160(vault) % 3 == 0
                    ? 0
                    : uint160(vault) % 3 == 1
                        ? 1
                        : 2
            );

            vm.prank(vault);
            if (!(allStatusesValid || uint160(vault) % 3 == 0)) {
                vm.expectRevert(abi.encodeWithSelector(
                    EulerConductor.VaultStatusViolation.selector,
                    vault,
                    uint160(vault) % 3 == 1
                        ? "vault status violation"
                        : ""
                ));
            }
            conductor.requireVaultStatusCheck(vault);
        }
    }

    function test_RequireVaultStatusCheckWhenDeferred(uint8 vaultsNumber, bool allStatusesValid) external {
        vm.assume(vaultsNumber > 0 && vaultsNumber <= 10);
        
        for (uint i = 0; i < vaultsNumber; i++) {
            address vault = address(new EulerVaultMock(address(conductor)));

            // check all the options: vault state is ok, vault state is violated with
            // controller returning false and reverting
            EulerVaultMock(vault).setVaultStatusState(
                allStatusesValid
                ? 0
                : uint160(vault) % 3 == 0
                    ? 0
                    : uint160(vault) % 3 == 1
                        ? 1
                        : 2
            );

            EulerVaultMock(vault).setVaultStatusState(1);
            conductor.setBatchDepth(2);

            vm.prank(vault);

            // even though the vault status state was set to 1 which should revert,
            // it doesn't because in checks deferral we only add the vaults to the set
            // so that the checks can be performed later
            conductor.requireVaultStatusCheck(vault);

            if (!(allStatusesValid || uint160(vault) % 3 == 0)) {
                // checks no longer deferred
                conductor.setBatchDepth(1);

                vm.prank(vault);
                vm.expectRevert(abi.encodeWithSelector(
                    EulerConductor.VaultStatusViolation.selector,
                    vault,
                    "vault status violation"
                ));
                conductor.requireVaultStatusCheck(vault);
            }   
        }
    }

    function test_RequireVaultStatusCheck_RevertIfNotVaultCalling(address randomMsgSender) external {
        address vault = address(new EulerVaultMock(address(conductor)));
        vm.assume(vault != randomMsgSender);

        EulerVaultMock(vault).setVaultStatusState(0);

        vm.prank(randomMsgSender);
        vm.expectRevert(EulerConductor.NotAuthorized.selector);
        conductor.requireVaultStatusCheck(vault);
    }


    function test_Batch(address alice, address bob, uint seed) external {
        vm.assume(!samePrimaryAccount(alice, bob));
        vm.assume(seed >= 3);

        Types.EulerBatchItem[] memory items = new Types.EulerBatchItem[](7);
        address controller = address(new EulerVaultMock(address(conductor)));
        address otherVault = address(new EulerVaultMock(address(conductor)));
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

        conductor.pushIntoExpectedAccountsChecked(alice);

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
        items[3].targetContract = otherVault;
        items[3].msgValue = 0;
        items[3].data = abi.encodeWithSelector(
            EulerVaultMock.requireChecks.selector,
            alicesSubAccount
        );

        items[4].allowError = false;
        items[4].onBehalfOfAccount = address(0);
        items[4].targetContract = controller;
        items[4].msgValue = seed / 3;
        items[4].data = abi.encodeWithSelector(
            EulerVaultMock.call.selector,
            otherVault,
            abi.encodeWithSelector(
                TargetMock.func.selector,
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
            TargetMock.func.selector,
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

        conductor.pushIntoExpectedAccountsChecked(alicesSubAccount);

        hoax(alice, seed);
        conductor.handlerBatch{value: seed}(items);

        assertTrue(EulerRegistryMock(registry).isRegistered(controller));
        assertTrue(conductor.isControllerEnabled(alice, controller));
        assertTrue(conductor.isControllerEnabled(alicesSubAccount, controller));
        assertTrue(conductor.accountOperators(alice, bob));
        assertEq(address(otherVault).balance, seed);

        conductor.reset();
        EulerVaultMock(controller).reset();
        EulerVaultMock(otherVault).reset();

        // -------------- SECOND BATCH -------------------------
        items = new Types.EulerBatchItem[](1);

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
        conductor.handlerBatch(items);

        // -------------- THIRD BATCH -------------------------
        items = new Types.EulerBatchItem[](1);

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
        conductor.handlerBatch(items);

        // the batch had no effect as we allowed error
        assertTrue(conductor.isControllerEnabled(alice, controller));

        conductor.reset();
        EulerVaultMock(controller).reset();
        EulerVaultMock(otherVault).reset();

        // -------------- FOURTH BATCH -------------------------
        items = new Types.EulerBatchItem[](3);

        items[0].allowError = false;
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = controller;
        items[0].msgValue = 0;
        items[0].data= abi.encodeWithSelector(
            EulerVaultMock.disableController.selector,
            alice
        );

        items[1].allowError = false;
        items[1].onBehalfOfAccount = address(0);
        items[1].targetContract = controller;
        items[1].msgValue = 0;
        items[1].data= abi.encodeWithSelector(
            EulerVaultMock.requireChecks.selector,
            bob
        );

        items[2].allowError = false;
        items[2].onBehalfOfAccount = bob;
        items[2].targetContract = otherVault;
        items[2].msgValue = 0;
        items[2].data= abi.encodeWithSelector(
            EulerVaultMock.requireChecks.selector,
            alicesSubAccount
        );

        vm.prank(bob);
        conductor.handlerBatch(items);
        assertFalse(conductor.isControllerEnabled(alice, controller));
    }

    function test_Batch_RevertIfDeferralDepthExceeded(address alice) external {
        address vault = address(new EulerVaultMock(address(conductor)));
        EulerRegistryMock(registry).setRegistered(vault, true);

        Types.EulerBatchItem[] memory items = new Types.EulerBatchItem[](9);

        for (int i = int(items.length - 1); i >= 0; --i) {
            uint j = uint(i);
            items[j].allowError = false;
            items[j].onBehalfOfAccount = alice;
            items[j].targetContract = address(conductor);
            items[j].msgValue = 0;

            if (j == items.length - 1) {
                Types.EulerBatchItem[] memory nestedItems = new Types.EulerBatchItem[](2);

                nestedItems[0].allowError = false;
                nestedItems[0].onBehalfOfAccount = address(0);
                nestedItems[0].targetContract = vault;
                nestedItems[0].msgValue = 0;
                nestedItems[0].data= abi.encodeWithSelector(
                    EulerVaultMock.requireChecks.selector,
                    alice
                );

                nestedItems[1].allowError = false;
                nestedItems[1].onBehalfOfAccount = address(0);
                nestedItems[1].targetContract = address(conductor);
                nestedItems[1].msgValue = 0;
                nestedItems[1].data= abi.encodeWithSelector(
                    EulerConductor.enableController.selector,
                    alice,
                    vault
                );

                items[j].data = abi.encodeWithSelector(
                    EulerConductor.batch.selector,
                    nestedItems
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
        vm.expectRevert(EulerConductor.BatchDepthViolation.selector);
        (bool success, ) = address(conductor).call(abi.encodeWithSelector(
            EulerConductorHandler.handlerBatch.selector,
            items
        ));
        assertTrue(success); // is true because of vm.expectRevert() above

        // should succeed when one less item. doesn't revert anymore,
        // but checks are performed only once, when the top level batch concludes
        Types.EulerBatchItem[] memory itemsOneLess = new Types.EulerBatchItem[](8);
        for (uint i = 1; i <= itemsOneLess.length; ++i) {
            itemsOneLess[i-1] = items[i];
        }

        vm.prank(alice);
        (success, ) = address(conductor).call(abi.encodeWithSelector(
            EulerConductorHandler.handlerBatch.selector,
            itemsOneLess
        ));
        assertTrue(success);
    }

    function test_Batch_RevertIfChecksInProgress(address alice) external {
        address vault = address(new EulerVaultMaliciousMock(address(conductor)));

        Types.EulerBatchItem[] memory items = new Types.EulerBatchItem[](1);
        items[0].allowError = false;
        items[0].onBehalfOfAccount = address(0);
        items[0].targetContract = vault;
        items[0].msgValue = 0;
        items[0].data= abi.encodeWithSelector(
            EulerVaultMock.requireChecks.selector,
            alice
        );

        // internal batch in the malicious vault reverted with ChecksReentrancy error,
        // check EulerVaultMaliciousMock implementation
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(
            EulerConductor.VaultStatusViolation.selector,
            vault,
            ""
        ));
        conductor.batch(items);
    }

    function test_BatchRevert_AND_BatchSimulation(address alice) external {
        Types.EulerBatchItem[] memory items = new Types.EulerBatchItem[](1);
        Types.EulerResult[] memory expectedBatchItemsResult = new Types.EulerResult[](1);
        Types.EulerResult[] memory expectedAccountsStatusResult = new Types.EulerResult[](1);
        Types.EulerResult[] memory expectedVaultsStatusResult = new Types.EulerResult[](1);

        address controller = address(new EulerVaultMock(address(conductor)));
        EulerRegistryMock(registry).setRegistered(controller, true);

        vm.prank(alice);
        conductor.enableController(alice, controller);

        items[0].allowError = false;
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = controller;
        items[0].msgValue = 0;
        items[0].data = abi.encodeWithSelector(
            EulerVaultMock.requireChecks.selector,
            alice
        );

        expectedBatchItemsResult[0].success = true;
        expectedBatchItemsResult[0].result = "";

        expectedAccountsStatusResult[0].success = true;
        expectedAccountsStatusResult[0].result = "";

        expectedVaultsStatusResult[0].success = true;
        expectedVaultsStatusResult[0].result = "";

        // regular batch doesn't revert
        vm.prank(alice);
        conductor.batch(items);

        {
            vm.prank(alice);
            try conductor.batchRevert(items) {
                assert(false);
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

        // invalidate both checks
        EulerVaultMock(controller).setVaultStatusState(1);
        EulerVaultMock(controller).setAccountStatusState(1);

        // update expected behavior
        expectedAccountsStatusResult[0].success = false;
        expectedAccountsStatusResult[0].result = abi.encodeWithSelector(
            EulerConductor.AccountStatusViolation.selector,
            alice,
            "account status violation"
        );
        
        expectedVaultsStatusResult[0].success = false;
        expectedVaultsStatusResult[0].result = abi.encodeWithSelector(
            EulerConductor.VaultStatusViolation.selector,
            controller,
            "vault status violation"
        );

        // regular batch reverts now
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(
            EulerConductor.AccountStatusViolation.selector,
            alice,
            "account status violation"
        ));
        conductor.batch(items);

        {
            vm.prank(alice);
            try conductor.batchRevert(items) {
                assert(false);
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
