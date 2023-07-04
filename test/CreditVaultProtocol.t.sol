// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/CreditVaultProtocol.sol";

contract TargetMock {
    function func(address cvp, address msgSender, uint msgValue, bool checksDeferred, address onBehalfOfAccount) external payable returns (uint) {
        // also tests getExecutionContext() from the CVP
        (bool _checksDeferred, address _onBehalfOfAccount) = ICVP(cvp).getExecutionContext();

        require(msg.sender == msgSender, "func/invalid-sender");
        require(msg.value == msgValue, "func/invalid-msg-value");
        require(_checksDeferred == checksDeferred, "func/invalid-checks-deferred");
        require(_onBehalfOfAccount == onBehalfOfAccount, "func/invalid-on-behalf-of-account");

        return msg.value;
    }
}

contract VaultMock is ICreditVault, TargetMock, Test {
    ICVP public immutable cvp;
    uint internal vaultStatusState;
    bool[] internal vaultStatusChecked;
    uint internal accountStatusState;
    address[] internal accountStatusChecked;

    constructor(ICVP _cvp) {
        cvp = _cvp;
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
        cvp.disableController(account);
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
        cvp.requireAccountStatusCheck(account);
        cvp.requireVaultStatusCheck();
    }

    function call(address target, bytes memory data) external payable {
        (bool success, ) = target.call{value: msg.value}(data);
        require(success, "call/failed");
    }
}

contract VaultMaliciousMock is ICreditVault {
    ICVP public immutable cvp;

    constructor(ICVP _cvp) {
        cvp = _cvp;
    }

    function disableController(address account) external override {}

    function checkVaultStatus() external override returns (bool, bytes memory) {
        // try to reenter the CVP batch. if it were possible, one could defer other vaults status checks
        // by entering a batch here and make the checkStatusAll() malfunction. possible attack:
        // - execute a batch with any item that calls checkVaultStatus() on vault A
        // - checkStatusAll() calls checkVaultStatus() on vault A
        // - vault A reenters a batch with any item that calls checkVaultStatus() on vault B
        // - because checks are deferred, checkVaultStatus() on vault B is not executed right away
        // - control is handed over back to checkStatusAll() which had numElements = 1 when entering the loop
        // - the loop ends and "delete vaultStatusChecks" is called removing the vault status check scheduled on vault B
        Types.BatchItem[] memory items = new Types.BatchItem[](1);
        items[0].allowError = false;
        items[0].onBehalfOfAccount = address(0);
        items[0].targetContract = address(0);
        items[0].msgValue = 0;
        items[0].data = "";

        try cvp.batch(items) {
            assert(false);
        } catch (bytes memory err) {
            assert(bytes4(err) == CreditVaultProtocol.ChecksReentrancy.selector);
            return (false, "");
        }
        return (true, "");
    }

    function checkAccountStatus(address, address[] memory) external pure override 
    returns (bool isValid, bytes memory data) {
        return (true, "");
    }

    function requireChecks(address account) external payable {
        cvp.requireAccountStatusCheck(account);
        cvp.requireVaultStatusCheck();
    }
}

contract CreditVaultProtocolHandler is CreditVaultProtocol {
    address[] expectedAccountsChecked;
    address[] expectedVaultsChecked;

    using Set for SetStorage;

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
        if (controllers.length == 1) VaultMock(controllers[0]).pushAccountStatusChecked(account);
    }

    function requireVaultStatusCheck() public override {
        super.requireVaultStatusCheck();

        expectedVaultsChecked.push(msg.sender);
    }

    function requireVaultStatusCheckInternal(address vault) internal override {
        super.requireVaultStatusCheckInternal(vault);

        VaultMock(vault).pushVaultStatusChecked();
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
            require(VaultMock(expectedVaultsChecked[i]).getVaultStatusChecked().length == 1, "verifyVaultStatusChecks");
        }
    }

    function verifyAccountStatusChecks() internal view {
        for (uint i = 0; i < expectedAccountsChecked.length; ++i) {
            address[] memory controllers = accountControllers[expectedAccountsChecked[i]].get();

            require(controllers.length <= 1, "verifyAccountStatusChecks/length");

            if (controllers.length == 0) continue;

            address[] memory accounts = VaultMock(controllers[0]).getAccountStatusChecked();

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

    function handlerDisableController(address account) external {
        super.disableController(account);

        if (executionContext.batchDepth != BATCH_DEPTH__INIT) return;

        expectedAccountsChecked.push(account == address(0) ? msg.sender : account);
        verifyStorage();
        verifyAccountStatusChecks();
    }

    function handlerBatch(BatchItem[] calldata items) public payable {
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

contract CreditVaultProtocolTest is Test {
    CreditVaultProtocolHandler cvp;

    event AccountOperatorSet(address indexed account, address indexed operator, bool isAuthorized);

    function samePrimaryAccount(address accountOne, address accountTwo) internal pure returns (bool) {
        return (uint160(accountOne) | 0xFF) == (uint160(accountTwo) | 0xFF);
    }

    function setUp() public {
        cvp = new CreditVaultProtocolHandler();
    }

    function test_SetAccountOperator(address alice, address operator) public {
        vm.assume(!samePrimaryAccount(alice, operator));

        for (uint i = 0; i < 256; ++i) {
            address account = address(uint160(uint160(alice) ^ i));

            assertFalse(cvp.accountOperators(account, operator));

            vm.prank(alice);
            vm.expectEmit(true, true, false, true, address(cvp));
            emit AccountOperatorSet(account, operator, true);
            cvp.setAccountOperator(account, operator, true);

            assertTrue(cvp.accountOperators(account, operator));

            vm.prank(alice);
            vm.expectEmit(true, true, false, true, address(cvp));
            emit AccountOperatorSet(account, operator, false);
            cvp.setAccountOperator(account, operator, false);

            assertFalse(cvp.accountOperators(account, operator));
        }
    }

    function test_SetAccountOperator_RevertIfSenderNotAuthorized(address alice, address operator) public {
        vm.assume(!samePrimaryAccount(alice, operator));

        address account = address(uint160(uint160(alice) ^ 256));

        assertFalse(cvp.accountOperators(account, operator));

        vm.prank(alice);
        vm.expectRevert(CreditVaultProtocol.NotAuthorized.selector);
        cvp.setAccountOperator(account, operator, true);
    }

    function test_SetAccountOperator_RevertIfOperatorIsSenderSubAccount(address alice, uint8 subAccountId) public {
        address operator = address(uint160(uint160(alice) ^ subAccountId));

        assertFalse(cvp.accountOperators(alice, operator));

        vm.prank(alice);
        vm.expectRevert(CreditVaultProtocol.InvalidAddress.selector);
        cvp.setAccountOperator(alice, operator, true);
    }

    function test_GetExecutionContext(uint8 depth, address account) external {
        vm.assume(depth > 0);
        vm.assume(account != address(0));

        (bool checksDeferred, address onBehalfOfAccount) = cvp.getExecutionContext();

        assertFalse(checksDeferred);
        assertEq(onBehalfOfAccount, address(0));
        
        cvp.setBatchDepth(depth);
        cvp.setOnBehalfOfAccount(account);

        (checksDeferred, onBehalfOfAccount) = cvp.getExecutionContext();
        
        assertEq(checksDeferred, depth > 1 ? true : false);
        assertEq(onBehalfOfAccount, account);
    }

    function test_GetExecutionContextExtended(address account, uint seed) external {
        vm.assume(account != address(0));

        address controller = address(new VaultMock(cvp));

        (
            bool checksDeferred, 
            address onBehalfOfAccount, 
            bool controllerEnabled
        ) = cvp.getExecutionContextExtended(account, controller);

        assertFalse(checksDeferred);
        assertEq(onBehalfOfAccount, address(0));
        assertFalse(controllerEnabled);
        
        if (seed % 2 == 0) {
            vm.prank(account);
            cvp.enableController(account, controller);
        }

        cvp.setBatchDepth(seed % 3 == 0 ? 2 : 1);
        cvp.setOnBehalfOfAccount(account);

        if (seed % 3 == 0) vm.prank(controller);

        (
            checksDeferred, 
            onBehalfOfAccount, 
            controllerEnabled
        ) = cvp.getExecutionContextExtended(account, controller);
        
        assertEq(checksDeferred, seed % 3 == 0 ? true : false);
        assertEq(onBehalfOfAccount, account);
        assertEq(controllerEnabled, seed % 2 == 0 ? true : false);
    }

    function test_GetExecutionContextExtended_RevertIfChecksDeferredAndMsgSenderNotVault(address account) external {
        vm.assume(account != address(0));

        address controller = address(new VaultMock(cvp));
        vm.assume(account != address(this));
        vm.assume(account != controller);
        
        vm.prank(account);
        cvp.enableController(account, controller);
        
        cvp.setBatchDepth(2);
        cvp.setOnBehalfOfAccount(account);

        vm.prank(account);
        vm.expectRevert(CreditVaultProtocol.DeferralViolation.selector);
        cvp.getExecutionContextExtended(account, controller);
    }

    function test_GetCollaterals(address alice) public {
        cvp.setBatchDepth(1);
        cvp.getCollaterals(alice);
    }

    function test_GetCollaterals_RevertIfChecksDeferred(address alice) public {
        cvp.setBatchDepth(2);
        vm.expectRevert(CreditVaultProtocol.DeferralViolation.selector);
        cvp.getCollaterals(alice);
    }

    function test_IsCollateralEnabled(address alice, address vault) public {
        cvp.setBatchDepth(1);
        cvp.isCollateralEnabled(alice, vault);
    }

    function test_IsCollateralEnabled_RevertIfChecksDeferred(address alice, address vault) public {
        cvp.setBatchDepth(2);
        vm.expectRevert(CreditVaultProtocol.DeferralViolation.selector);
        cvp.isCollateralEnabled(alice, vault);
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
            cvp.setAccountOperator(account, msgSender, true);
        }

        // enable a controller to check if account status check works properly
        address controller = address(new VaultMock(cvp));
        if (seed % 3 == 0) {
            vm.prank(alice);
            cvp.enableController(account, controller);
        }

        // enabling collaterals
        for (uint i = 1; i <= numberOfVaults; ++i) {
            cvp.reset();
            VaultMock(controller).reset();
            address[] memory collateralsPre = cvp.getCollaterals(account);

            address vault = i % 5 == 0
                ? collateralsPre[seed % collateralsPre.length]
                : address(new VaultMock(cvp));

            bool alreadyEnabled = cvp.isCollateralEnabled(account, vault);

            assert((alreadyEnabled && i % 5 == 0) || (!alreadyEnabled && i % 5 != 0));

            vm.prank(msgSender);
            cvp.handlerEnableCollateral(account, vault);

            address[] memory collateralsPost = cvp.getCollaterals(account);

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
        while (cvp.getCollaterals(account).length > 0) {
            cvp.reset();
            VaultMock(controller).reset();
            address[] memory collateralsPre = cvp.getCollaterals(account);
            address vault = collateralsPre[seed % collateralsPre.length];

            vm.prank(msgSender);
            cvp.handlerDisableCollateral(account, vault);

            address[] memory collateralsPost = cvp.getCollaterals(account);

            assertEq(collateralsPost.length, collateralsPre.length - 1);

            for (uint j = 0; j < collateralsPost.length; ++j) {
                assertNotEq(collateralsPost[j], vault);
            }
        }
    }

    function test_CollateralsManagement_RevertIfNotOwnerAndNotOperator(address alice, address bob) public {
        vm.assume(!samePrimaryAccount(alice, bob));

        address vault = address(new VaultMock(cvp));

        vm.prank(alice);
        vm.expectRevert(CreditVaultProtocol.NotAuthorized.selector);
        cvp.handlerEnableCollateral(bob, vault);

        vm.prank(alice);
        vm.expectRevert(CreditVaultProtocol.NotAuthorized.selector);
        cvp.handlerDisableCollateral(bob, vault);

        vm.prank(bob);
        cvp.setAccountOperator(bob, alice, true);

        vm.prank(alice);
        cvp.handlerEnableCollateral(bob, vault);

        vm.prank(alice);
        cvp.handlerDisableCollateral(bob, vault);
    }

    function test_CollateralsManagement_RevertIfAccountStatusViolated(address alice) public {
        address vault = address(new VaultMock(cvp));
        address controller = address(new VaultMock(cvp));

        vm.prank(alice);
        cvp.enableController(alice, controller);
        VaultMock(controller).reset();

        VaultMock(controller).setAccountStatusState(1); // account status is violated

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultProtocol.AccountStatusViolation.selector,
                alice,
                "account status violation"
            )
        );
        cvp.handlerEnableCollateral(alice, vault);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultProtocol.AccountStatusViolation.selector,
                alice,
                "account status violation"
            )
        );
        cvp.handlerDisableCollateral(alice, vault);

        VaultMock(controller).setAccountStatusState(0); // account status is NOT violated

        vm.prank(alice);
        cvp.handlerEnableCollateral(alice, vault);
        VaultMock(controller).reset(); // reset so that the account status check verification succeeds

        vm.prank(alice);
        cvp.handlerDisableCollateral(alice, vault);
    }

    function test_GetControllers(address alice) public {
        cvp.setBatchDepth(1);
        cvp.getControllers(alice);
    }

    function test_GetControllers_RevertIfChecksDeferred(address alice) public {
        cvp.setBatchDepth(2);
        vm.expectRevert(CreditVaultProtocol.DeferralViolation.selector);
        cvp.getControllers(alice);
    }

    function test_IsControllerEnabled(address alice) public {
        address vault = address(new VaultMock(cvp));
        cvp.setBatchDepth(1);
        cvp.isControllerEnabled(alice, vault);

        // even though checks are deferred, the function succeeds if called by the vault asking if vault enabled
        // as a controller
        cvp.setBatchDepth(2);
        VaultMock(vault).call(
            address(cvp),
            abi.encodeWithSelector(
                cvp.isControllerEnabled.selector,
                alice,
                vault
            )
        );
    }

    function test_IsControllerEnabled_RevertIfChecksDeferredAndMsgSenderNotVault(address alice, address vault) public {
        vm.assume(alice != vault);
        vm.assume(address(this) != vault);

        cvp.setBatchDepth(2);

        vm.prank(alice);
        vm.expectRevert(CreditVaultProtocol.DeferralViolation.selector);
        cvp.isControllerEnabled(alice, vault);
    }

    function test_ControllersManagement(address alice, uint8 subAccountId, uint seed) public {
        vm.assume(seed > 1000);

        address account = address(uint160(uint160(alice) ^ subAccountId));

        // test controllers management with use of an operator
        address msgSender = alice;
        if (seed % 2 == 0 && !samePrimaryAccount(account, address(uint160(seed)))) {
            msgSender = address(uint160(seed));
            vm.prank(alice);
            cvp.setAccountOperator(account, msgSender, true);
        }

        // enabling controller
        address vault = address(new VaultMock(cvp));

        assertFalse(cvp.isControllerEnabled(account, vault));
        address[] memory controllersPre = cvp.getControllers(account);

        vm.prank(msgSender);
        cvp.handlerEnableController(account, vault);

        address[] memory controllersPost = cvp.getControllers(account);

        assertEq(controllersPost.length, controllersPre.length + 1);
        assertEq(controllersPost[controllersPost.length - 1], vault);
        assertTrue(cvp.isControllerEnabled(account, vault));

        // enabling the same controller again should succeed (duplicate will not be added)
        cvp.reset();
        VaultMock(vault).reset();
        assertTrue(cvp.isControllerEnabled(account, vault));
        controllersPre = cvp.getControllers(account);

        vm.prank(msgSender);
        cvp.handlerEnableController(account, vault);

        controllersPost = cvp.getControllers(account);

        assertEq(controllersPost.length, controllersPre.length);
        assertEq(controllersPost[0], controllersPre[0]);
        assertTrue(cvp.isControllerEnabled(account, vault));

        // trying to enable second controller will throw on the account status check
        address otherVault = address(new VaultMock(cvp));

        vm.prank(msgSender);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultProtocol.ControllerViolation.selector,
                account
            )
        );
        cvp.handlerEnableController(account, otherVault);

        // only the controller vault can disable itself
        cvp.reset();
        VaultMock(vault).reset();
        assertTrue(cvp.isControllerEnabled(account, vault));
        controllersPre = cvp.getControllers(account);

        vm.prank(msgSender);
        VaultMock(vault).call(
            address(cvp),
            abi.encodeWithSelector(
                cvp.handlerDisableController.selector,
                account
            )
        );

        controllersPost = cvp.getControllers(account);

        assertEq(controllersPost.length, controllersPre.length - 1);
        assertEq(controllersPost.length, 0);
        assertFalse(cvp.isControllerEnabled(account, vault));
    }

    function test_EnableController_RevertIfNotOwnerAndNotOperator(address alice, address bob) public {
        vm.assume(!samePrimaryAccount(alice, bob));

        address vault = address(new VaultMock(cvp));

        vm.prank(alice);
        vm.expectRevert(CreditVaultProtocol.NotAuthorized.selector);
        cvp.handlerEnableController(bob, vault);

        vm.prank(bob);
        cvp.setAccountOperator(bob, alice, true);

        vm.prank(alice);
        cvp.handlerEnableController(bob, vault);
    }

    function test_ControllersManagement_RevertIfAccountStatusViolated(address alice) public {
        address vault = address(new VaultMock(cvp));

        VaultMock(vault).setAccountStatusState(1); // account status is violated

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultProtocol.AccountStatusViolation.selector,
                alice,
                "account status violation"
            )
        );
        cvp.handlerEnableController(alice, vault);

        vm.prank(alice);
        // succeeds as there's no controller to perform the account status check
        VaultMock(vault).call(
            address(cvp),
            abi.encodeWithSelector(
                cvp.handlerDisableController.selector,
                alice
            )
        );

        cvp.reset();
        VaultMock(vault).reset();
        VaultMock(vault).setAccountStatusState(1); // account status is still violated

        vm.prank(alice);
        // succeeds as there's no controller to perform the account status check
        cvp.handlerEnableCollateral(alice, vault);

        cvp.reset();
        VaultMock(vault).reset(); // account status is no longer violated in order to enable controller

        vm.prank(alice);
        cvp.handlerEnableController(alice, vault);

        cvp.reset();
        VaultMock(vault).reset();
        VaultMock(vault).setAccountStatusState(1); // account status is violated again

        vm.prank(alice);
        // it won't succeed as this time we have a controller so the account status check is performed
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultProtocol.AccountStatusViolation.selector,
                alice,
                "account status violation"
            )
        );
        cvp.handlerEnableCollateral(alice, vault);
    }

    function test_Call(address alice, uint96 seed) public {
        address account;
        if (seed % 2 == 0) {
            // in this case the account is not alice's sub-account thus alice must be an operator
            account = address(uint160(uint160(alice) ^ 256));
            vm.prank(account);
            cvp.setAccountOperator(account, alice, true);
        } else {
            // in this case the account is alice's sub-account
            account = address(uint160(uint160(alice) ^ (seed % 256)));
        }
        vm.assume(account != address(0));

        address targetContract = address(new TargetMock());
        vm.assume(targetContract != address(cvp));

        bytes memory data = abi.encodeWithSelector(
            TargetMock(targetContract).func.selector,
            address(cvp),
            address(cvp),
            seed,
            false,
            account
        );

        hoax(alice, seed);
        (bool success, bytes memory result) = cvp.handlerCall{value: seed}(
            targetContract,
            account,
            data
        );

        assertTrue(success);
        assertEq(abi.decode(result, (uint)), seed);

        // should also succeed if the onBehalfOfAccount address passed is 0. it should be replaced with msg.sender
        data = abi.encodeWithSelector(
            TargetMock(targetContract).func.selector,
            address(cvp),
            address(cvp),
            seed,
            false,
            alice
        );

        hoax(alice, seed);
        (success, result) = cvp.handlerCall{value: seed}(
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
        vm.assume(targetContract != address(cvp));

        bytes memory data = abi.encodeWithSelector(
            TargetMock(targetContract).func.selector,
            address(cvp),
            address(cvp),
            seed,
            false,
            alice
        );

        hoax(alice, seed);
        vm.expectRevert(CreditVaultProtocol.NotAuthorized.selector);
        (bool success,) = cvp.handlerCall{value: seed}(
            targetContract,
            bob,
            data
        );

        assertFalse(success);
    }


    function test_Call_RevertIfTargetContractInvalid(address alice, uint seed) public {
        vm.assume(alice != address(0));

        // target contract is the CVP
        address targetContract = address(cvp);

        bytes memory data = abi.encodeWithSelector(
            TargetMock(targetContract).func.selector,
            address(cvp),
            targetContract,
            seed,
            false,
            alice
        );

        hoax(alice, seed);
        vm.expectRevert(CreditVaultProtocol.InvalidAddress.selector);

        (bool success,) = cvp.handlerCall{value: seed}(
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
            address(cvp),
            targetContract,
            seed,
            false,
            alice
        );

        hoax(alice, seed);
        vm.expectRevert(CreditVaultProtocol.InvalidAddress.selector);

        (success,) = cvp.handlerCall{value: seed}(
            targetContract,
            alice,
            data
        );

        assertFalse(success);
    }

    function test_CallFromControllerToCollateral(address alice, uint96 seed) public {
        vm.assume(alice != address(0));

        address collateral = address(new VaultMock(cvp));
        address controller = address(new VaultMock(cvp));

        vm.prank(alice);
        cvp.enableCollateral(alice, collateral);

        vm.prank(alice);
        cvp.enableController(alice, controller);

        bytes memory data = abi.encodeWithSelector(
            TargetMock(collateral).func.selector,
            address(cvp),
            address(cvp),
            seed,
            false,
            alice
        );

        hoax(controller, seed);
        (bool success, bytes memory result) = cvp.handlerCallFromControllerToCollateral{value: seed}(
            collateral,
            alice,
            data
        );

        assertTrue(success);
        assertEq(abi.decode(result, (uint)), seed);

        // should also succeed if the onBehalfOfAccount address passed is 0. it should be replaced with msg.sender
        // note that in this case the controller tries to act on behalf itself
        vm.prank(controller);
        cvp.enableCollateral(controller, collateral);

        vm.prank(controller);
        cvp.enableController(controller, controller);

        data = abi.encodeWithSelector(
            TargetMock(collateral).func.selector,
            address(cvp),
            address(cvp),
            seed,
            false,
            controller
        );

        hoax(controller, seed);
        (success, result) = cvp.handlerCallFromControllerToCollateral{value: seed}(
            collateral,
            address(0),
            data
        );

        assertTrue(success);
        assertEq(abi.decode(result, (uint)), seed);
    }

    function test_CallFromControllerToCollateral_RevertIfNoControllerEnabled(address alice, uint seed) public {
        vm.assume(alice != address(0));

        address collateral = address(new VaultMock(cvp));
        address controller = address(new VaultMock(cvp));

        vm.prank(alice);
        cvp.enableCollateral(alice, collateral);

        bytes memory data = abi.encodeWithSelector(
            TargetMock(collateral).func.selector,
            address(cvp),
            address(cvp),
            seed,
            false,
            alice
        );

        hoax(controller, seed);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultProtocol.ControllerViolation.selector,
                alice
            )
        );
        (bool success,) = cvp.handlerCallFromControllerToCollateral{value: seed}(
            collateral,
            alice,
            data
        );

        assertFalse(success);
    }

    function test_CallFromControllerToCollateral_RevertIfMultipleControllersEnabled(address alice, uint seed) public {
        vm.assume(alice != address(0));

        address collateral = address(new VaultMock(cvp));
        address controller_1 = address(new VaultMock(cvp));
        address controller_2 = address(new VaultMock(cvp));

        // mock checks deferred to enable multiple controllers
        cvp.setBatchDepth(2);

        vm.prank(alice);
        cvp.enableCollateral(alice, collateral);

        vm.prank(alice);
        cvp.enableController(alice, controller_1);

        vm.prank(alice);
        cvp.enableController(alice, controller_2);

        bytes memory data = abi.encodeWithSelector(
            TargetMock(collateral).func.selector,
            address(cvp),
            address(cvp),
            seed,
            false,
            alice
        );

        hoax(controller_1, seed);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultProtocol.ControllerViolation.selector,
                alice
            )
        );
        (bool success,) = cvp.handlerCallFromControllerToCollateral{value: seed}(
            collateral,
            alice,
            data
        );

        assertFalse(success);
    }

    function test_CallFromControllerToCollateral_RevertIfMsgSenderIsNotEnabledController(address alice, address randomAddress, uint seed) public {
        vm.assume(alice != address(0));

        address collateral = address(new VaultMock(cvp));
        address controller = address(new VaultMock(cvp));

        vm.assume(randomAddress != controller);

        vm.prank(alice);
        cvp.enableCollateral(alice, collateral);

        vm.prank(alice);
        cvp.enableController(alice, controller);

        bytes memory data = abi.encodeWithSelector(
            TargetMock(collateral).func.selector,
            address(cvp),
            address(cvp),
            seed,
            false,
            alice
        );

        hoax(randomAddress, seed);
        vm.expectRevert(abi.encodeWithSelector(CreditVaultProtocol.NotAuthorized.selector));
        (bool success,) = cvp.handlerCallFromControllerToCollateral{value: seed}(
            collateral,
            alice,
            data
        );

        assertFalse(success);
    }

    function test_CallFromControllerToCollateral_RevertIfTargetContractIsNotEnabledCollateral(address alice, address targetContract, uint seed) public {
        vm.assume(alice != address(0));

        address collateral = address(new VaultMock(cvp));
        address controller = address(new VaultMock(cvp));

        vm.assume(targetContract != collateral);

        vm.prank(alice);
        cvp.enableCollateral(alice, collateral);

        vm.prank(alice);
        cvp.enableController(alice, controller);

        bytes memory data = abi.encodeWithSelector(
            TargetMock(collateral).func.selector,
            address(cvp),
            address(cvp),
            seed,
            false,
            alice
        );

        hoax(controller, seed);
        vm.expectRevert(abi.encodeWithSelector(CreditVaultProtocol.NotAuthorized.selector));
        (bool success,) = cvp.handlerCallFromControllerToCollateral{value: seed}(
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

            address controller = address(new VaultMock(cvp));

            if (!allStatusesValid) {
                vm.prank(account);
                cvp.enableController(account, controller);
            }

            // check all the options: account state is ok, account state is violated with
            // controller returning false and reverting
            VaultMock(controller).setAccountStatusState(
                allStatusesValid
                ? 0
                : uint160(account) % 3 == 0
                    ? 0
                    : uint160(account) % 3 == 1
                        ? 1
                        : 2
            );

            if (!(allStatusesValid || uint160(account) % 3 == 0)) {
                assertFalse(cvp.checkAccountStatus(account));
            } else {
                assertTrue(cvp.checkAccountStatus(account));
            }
        }

        bool[] memory isValid = cvp.checkAccountsStatus(accounts);
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

            address controller = address(new VaultMock(cvp));

            if (!allStatusesValid) {
                vm.prank(account);
                cvp.enableController(account, controller);
            }

            // check all the options: account state is ok, account state is violated with
            // controller returning false and reverting
            VaultMock(controller).setAccountStatusState(
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
                    CreditVaultProtocol.AccountStatusViolation.selector,
                    account,
                    uint160(account) % 3 == 1
                        ? "account status violation"
                        : ""
                ));
            }
            cvp.requireAccountStatusCheck(account);
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
                CreditVaultProtocol.AccountStatusViolation.selector,
                invalidAccount,
                uint160(invalidAccount) % 3 == 1
                    ? "account status violation"
                    : ""
            ));
        }
        cvp.requireAccountsStatusCheck(accounts);
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

            cvp.setBatchDepth(1);

            address controller = address(new VaultMock(cvp));

            vm.prank(account);
            cvp.enableController(account, controller);
            VaultMock(controller).setAccountStatusState(1);

            cvp.setBatchDepth(2);

            // even though the account status state was set to 1 which should revert,
            // it doesn't because in checks deferral we only add the accounts to the set
            // so that the checks can be performed later
            cvp.requireAccountStatusCheck(account);
        }

        cvp.requireAccountsStatusCheck(accounts);

        // checks no longer deferred
        cvp.setBatchDepth(1);

        vm.expectRevert(abi.encodeWithSelector(
            CreditVaultProtocol.AccountStatusViolation.selector,
            accounts[0],
            "account status violation"
        ));
        cvp.requireAccountsStatusCheck(accounts);
    }

    function test_RequireVaultStatusCheck(uint8 vaultsNumber, bool allStatusesValid) external {
        vm.assume(vaultsNumber > 0 && vaultsNumber <= 10);
        
        for (uint i = 0; i < vaultsNumber; i++) {
            address vault = address(new VaultMock(cvp));

            // check all the options: vault state is ok, vault state is violated with
            // controller returning false and reverting
            VaultMock(vault).setVaultStatusState(
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
                    CreditVaultProtocol.VaultStatusViolation.selector,
                    vault,
                    uint160(vault) % 3 == 1
                        ? "vault status violation"
                        : ""
                ));
            }
            cvp.requireVaultStatusCheck();
        }
    }

    function test_RequireVaultStatusCheckWhenDeferred(uint8 vaultsNumber, bool allStatusesValid) external {
        vm.assume(vaultsNumber > 0 && vaultsNumber <= 10);
        
        for (uint i = 0; i < vaultsNumber; i++) {
            address vault = address(new VaultMock(cvp));

            // check all the options: vault state is ok, vault state is violated with
            // controller returning false and reverting
            VaultMock(vault).setVaultStatusState(
                allStatusesValid
                ? 0
                : uint160(vault) % 3 == 0
                    ? 0
                    : uint160(vault) % 3 == 1
                        ? 1
                        : 2
            );

            VaultMock(vault).setVaultStatusState(1);
            cvp.setBatchDepth(2);

            vm.prank(vault);

            // even though the vault status state was set to 1 which should revert,
            // it doesn't because in checks deferral we only add the vaults to the set
            // so that the checks can be performed later
            cvp.requireVaultStatusCheck();

            if (!(allStatusesValid || uint160(vault) % 3 == 0)) {
                // checks no longer deferred
                cvp.setBatchDepth(1);

                vm.prank(vault);
                vm.expectRevert(abi.encodeWithSelector(
                    CreditVaultProtocol.VaultStatusViolation.selector,
                    vault,
                    "vault status violation"
                ));
                cvp.requireVaultStatusCheck();
            }   
        }
    }


    function test_Batch(address alice, address bob, uint seed) external {
        vm.assume(!samePrimaryAccount(alice, bob));
        vm.assume(seed >= 3);

        Types.BatchItem[] memory items = new Types.BatchItem[](6);
        address controller = address(new VaultMock(cvp));
        address otherVault = address(new VaultMock(cvp));
        address alicesSubAccount = address(uint160(alice) ^ 0x10);

        vm.assume(bob != controller);

        // -------------- FIRST BATCH -------------------------
        items[0].allowError = false;
        items[0].onBehalfOfAccount = address(0);
        items[0].targetContract = address(cvp);
        items[0].msgValue = 0;
        items[0].data = abi.encodeWithSelector(
            cvp.enableController.selector,
            alice,
            controller
        );

        cvp.pushIntoExpectedAccountsChecked(alice);

        items[1].allowError = false;
        items[1].onBehalfOfAccount = alice;
        items[1].targetContract = address(cvp);
        items[1].msgValue = 0;
        items[1].data = abi.encodeWithSelector(
            cvp.setAccountOperator.selector,
            alice,
            bob,
            true
        );

        items[2].allowError = false;
        items[2].onBehalfOfAccount = alicesSubAccount;
        items[2].targetContract = otherVault;
        items[2].msgValue = 0;
        items[2].data = abi.encodeWithSelector(
            VaultMock.requireChecks.selector,
            alicesSubAccount
        );

        items[3].allowError = false;
        items[3].onBehalfOfAccount = address(0);
        items[3].targetContract = controller;
        items[3].msgValue = seed / 3;
        items[3].data = abi.encodeWithSelector(
            VaultMock.call.selector,
            otherVault,
            abi.encodeWithSelector(
                TargetMock.func.selector,
                address(cvp),
                controller,
                seed / 3,
                true,
                alice
            )
        );

        items[4].allowError = false;
        items[4].onBehalfOfAccount = alice;
        items[4].targetContract = otherVault;
        items[4].msgValue = type(uint).max;
        items[4].data = abi.encodeWithSelector(
            TargetMock.func.selector,
            address(cvp),
            address(cvp),
            seed - seed / 3,
            true,
            alice
        );

        items[5].allowError = false;
        items[5].onBehalfOfAccount = alicesSubAccount;
        items[5].targetContract = address(cvp);
        items[5].msgValue = 0;
        items[5].data = abi.encodeWithSelector(
            cvp.enableController.selector,
            alicesSubAccount,
            controller
        );

        cvp.pushIntoExpectedAccountsChecked(alicesSubAccount);

        hoax(alice, seed);
        cvp.handlerBatch{value: seed}(items);

        assertTrue(cvp.isControllerEnabled(alice, controller));
        assertTrue(cvp.isControllerEnabled(alicesSubAccount, controller));
        assertTrue(cvp.accountOperators(alice, bob));
        assertEq(address(otherVault).balance, seed);

        cvp.reset();
        VaultMock(controller).reset();
        VaultMock(otherVault).reset();

        // -------------- SECOND BATCH -------------------------
        items = new Types.BatchItem[](1);

        items[0].allowError = false;
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = address(cvp);
        items[0].msgValue = 0;
        items[0].data= abi.encodeWithSelector(
            cvp.call.selector,
            address(cvp),
            alice,
            ""
        );

        vm.prank(bob);
        vm.expectRevert(CreditVaultProtocol.InvalidAddress.selector);
        cvp.handlerBatch(items);

        // -------------- THIRD BATCH -------------------------
        items = new Types.BatchItem[](1);

        items[0].allowError = true;
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = address(cvp);
        items[0].msgValue = 0;
        items[0].data= abi.encodeWithSelector(
            cvp.call.selector,
            address(cvp),
            alice,
            ""
        );

        // no rever this time as error allowed
        vm.prank(bob);
        cvp.handlerBatch(items);

        cvp.reset();
        VaultMock(controller).reset();
        VaultMock(otherVault).reset();

        // -------------- FOURTH BATCH -------------------------
        items = new Types.BatchItem[](3);

        items[0].allowError = false;
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = controller;
        items[0].msgValue = 0;
        items[0].data= abi.encodeWithSelector(
            VaultMock.disableController.selector,
            alice
        );

        items[1].allowError = false;
        items[1].onBehalfOfAccount = address(0);
        items[1].targetContract = controller;
        items[1].msgValue = 0;
        items[1].data= abi.encodeWithSelector(
            VaultMock.requireChecks.selector,
            bob
        );

        items[2].allowError = false;
        items[2].onBehalfOfAccount = bob;
        items[2].targetContract = otherVault;
        items[2].msgValue = 0;
        items[2].data= abi.encodeWithSelector(
            VaultMock.requireChecks.selector,
            alicesSubAccount
        );

        vm.prank(bob);
        cvp.handlerBatch(items);
        assertFalse(cvp.isControllerEnabled(alice, controller));
    }

    function test_Batch_RevertIfDeferralDepthExceeded(address alice) external {
        address vault = address(new VaultMock(cvp));

        Types.BatchItem[] memory items = new Types.BatchItem[](9);

        for (int i = int(items.length - 1); i >= 0; --i) {
            uint j = uint(i);
            items[j].allowError = false;
            items[j].onBehalfOfAccount = alice;
            items[j].targetContract = address(cvp);
            items[j].msgValue = 0;

            if (j == items.length - 1) {
                Types.BatchItem[] memory nestedItems = new Types.BatchItem[](2);

                nestedItems[0].allowError = false;
                nestedItems[0].onBehalfOfAccount = address(0);
                nestedItems[0].targetContract = vault;
                nestedItems[0].msgValue = 0;
                nestedItems[0].data= abi.encodeWithSelector(
                    VaultMock.requireChecks.selector,
                    alice
                );

                nestedItems[1].allowError = false;
                nestedItems[1].onBehalfOfAccount = address(0);
                nestedItems[1].targetContract = address(cvp);
                nestedItems[1].msgValue = 0;
                nestedItems[1].data= abi.encodeWithSelector(
                    cvp.enableController.selector,
                    alice,
                    vault
                );

                items[j].data = abi.encodeWithSelector(
                    cvp.batch.selector,
                    nestedItems
                );
            } else {
                Types.BatchItem[] memory nestedItems = new Types.BatchItem[](1);
                nestedItems[0] = items[j+1];

                items[j].data = abi.encodeWithSelector(
                    cvp.batch.selector,
                    nestedItems
                );
            }
        }

        vm.prank(alice);
        vm.expectRevert(CreditVaultProtocol.BatchDepthViolation.selector);
        (bool success, ) = address(cvp).call(abi.encodeWithSelector(
            cvp.handlerBatch.selector,
            items
        ));
        assertTrue(success); // is true because of vm.expectRevert() above

        // should succeed when one less item. doesn't revert anymore,
        // but checks are performed only once, when the top level batch concludes
        Types.BatchItem[] memory itemsOneLess = new Types.BatchItem[](8);
        for (uint i = 1; i <= itemsOneLess.length; ++i) {
            itemsOneLess[i-1] = items[i];
        }

        vm.prank(alice);
        (success, ) = address(cvp).call(abi.encodeWithSelector(
            cvp.handlerBatch.selector,
            itemsOneLess
        ));
        assertTrue(success);
    }

    function test_Batch_RevertIfChecksInProgress(address alice) external {
        address vault = address(new VaultMaliciousMock(cvp));

        Types.BatchItem[] memory items = new Types.BatchItem[](1);
        items[0].allowError = false;
        items[0].onBehalfOfAccount = address(0);
        items[0].targetContract = vault;
        items[0].msgValue = 0;
        items[0].data= abi.encodeWithSelector(
            VaultMock.requireChecks.selector,
            alice
        );

        // internal batch in the malicious vault reverted with ChecksReentrancy error,
        // check VaultMaliciousMock implementation
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(
            CreditVaultProtocol.VaultStatusViolation.selector,
            vault,
            ""
        ));
        cvp.batch(items);
    }

    function test_BatchRevert_AND_BatchSimulation(address alice) external {
        Types.BatchItem[] memory items = new Types.BatchItem[](1);
        Types.BatchResult[] memory expectedBatchItemsResult = new Types.BatchResult[](1);
        Types.BatchResult[] memory expectedAccountsStatusResult = new Types.BatchResult[](1);
        Types.BatchResult[] memory expectedVaultsStatusResult = new Types.BatchResult[](1);

        address controller = address(new VaultMock(cvp));

        vm.prank(alice);
        cvp.enableController(alice, controller);

        items[0].allowError = false;
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = controller;
        items[0].msgValue = 0;
        items[0].data = abi.encodeWithSelector(
            VaultMock.requireChecks.selector,
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
        cvp.batch(items);

        {
            vm.prank(alice);
            try cvp.batchRevert(items) {
                assert(false);
            } catch (bytes memory err) {
                assertEq(bytes4(err), CreditVaultProtocol.RevertedBatchResult.selector);

                assembly { err := add(err, 4) }
                (
                    Types.BatchResult[] memory batchItemsResult,
                    Types.BatchResult[] memory accountsStatusResult,
                    Types.BatchResult[] memory vaultsStatusResult 
                ) = abi.decode(err, (Types.BatchResult[], Types.BatchResult[], Types.BatchResult[]));
                
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
                Types.BatchResult[] memory batchItemsResult,
                Types.BatchResult[] memory accountsStatusResult,
                Types.BatchResult[] memory vaultsStatusResult 
            ) = cvp.batchSimulation(items);

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
        VaultMock(controller).setVaultStatusState(1);
        VaultMock(controller).setAccountStatusState(1);

        // update expected behavior
        expectedAccountsStatusResult[0].success = false;
        expectedAccountsStatusResult[0].result = abi.encodeWithSelector(
            CreditVaultProtocol.AccountStatusViolation.selector,
            alice,
            "account status violation"
        );
        
        expectedVaultsStatusResult[0].success = false;
        expectedVaultsStatusResult[0].result = abi.encodeWithSelector(
            CreditVaultProtocol.VaultStatusViolation.selector,
            controller,
            "vault status violation"
        );

        // regular batch reverts now
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(
            CreditVaultProtocol.AccountStatusViolation.selector,
            alice,
            "account status violation"
        ));
        cvp.batch(items);

        {
            vm.prank(alice);
            try cvp.batchRevert(items) {
                assert(false);
            } catch (bytes memory err) {
                assertEq(bytes4(err), CreditVaultProtocol.RevertedBatchResult.selector);

                assembly { err := add(err, 4) }
                (
                    Types.BatchResult[] memory batchItemsResult,
                    Types.BatchResult[] memory accountsStatusResult,
                    Types.BatchResult[] memory vaultsStatusResult 
                ) = abi.decode(err, (Types.BatchResult[], Types.BatchResult[], Types.BatchResult[]));
                
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
                Types.BatchResult[] memory batchItemsResult,
                Types.BatchResult[] memory accountsStatusResult,
                Types.BatchResult[] memory vaultsStatusResult 
            ) = cvp.batchSimulation(items);

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
