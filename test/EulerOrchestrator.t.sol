// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/EulerOrchestrator.sol";
import "../src/Types.sol";
import "../src/Array.sol";

contract TargetMock {
    function executeExample(address orchestrator, bool expectedChecksDeferred, Types.EulerBatchItem memory item) external payable {
        address targetAccount;
        bool checksDeferred;
        assembly {
            targetAccount := shr(96, calldataload(sub(calldatasize(), 40)))
            checksDeferred := shr(96, calldataload(sub(calldatasize(), 1)))
        }

        assert(msg.sender == orchestrator);
        assert(targetAccount == item.targetAccount);
        assert(address(this) == item.targetContract);
        assert(msg.value == item.msgValue);
        assert(checksDeferred == expectedChecksDeferred);
    }
}

contract EulerRegistryMock is IEulerVaultRegistry {
    mapping(address => bool) public isRegistered;

    function setRegistered(address vault, bool registered) external {
        isRegistered[vault] = registered;
    }
}

contract EulerVaultMock is TargetMock, Test {
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

    function getAccountStatusChecked() external view returns (address[] memory) {
        return accountStatusChecked;
    }

    function getHooksCalled() external view returns (uint[] memory) {
        return hooksCalled;
    }

    function checkAccountStatus(address, address[] memory) external view returns (bool isValid) {
        if (accountStatusState == 0) return true;
        else if (accountStatusState == 1) return false;
        else revert("invalid");
    }
    
    function hook(uint hookNumber, bytes memory data) external returns (bytes memory result) {
        if (hookNumber == 1) {
            assert(abi.decode(data, (uint)) == 0);
        } else if (hookNumber == 1) {
            assert(abi.decode(data, (uint)) == 1);
        } else {
            revert("unexpected hook number");
        }
        
        hooksCalled.push(hookNumber);
        return abi.encode(abi.decode(data, (uint)) + 1);
    }

    function call(address target, bytes memory data) external payable {
        (bool success,) = target.call{value: msg.value}(data);
        assert(success);
    }
}

contract DeferredChecks is IDeferredChecks {
    bool public checksDeferred;

    function reset() external {
        checksDeferred = false;
    }

    function onDeferredChecks(bytes memory) external payable {
        checksDeferred = true;
    }
}

contract EulerOrchestratorHandler is EulerOrchestrator {
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

    constructor(address admin, address registry) EulerOrchestrator(admin, registry) {}

    function setChecksDeferred(bool deferred) external {
        checksDeferred = deferred;
    }

    function requireAccountStatusCheckInternal(address account) internal override {
        super.requireAccountStatusCheckInternal(account);

        address[] memory conductors = accountConductors[account].getArray();
        if (conductors.length == 1) EulerVaultMock(conductors[0]).pushAccountStatusChecked(account);
    }

    function verifyTransientStorage(VaultStatusCheck[] memory vsc) internal view {
        assert(checksDeferred == false);
        assert(accountStatusChecks.numElements == 0);
        assert(accountStatusChecks.firstElement == address(0));

        for (uint i = 0; i < 20; ++i) {
            assert(accountStatusChecks.elements[i] == address(0));
        }

        assert(vaultStatusChecks.numElements == 0);
        assert(vaultStatusChecks.firstElement == address(0));

        for (uint i = 0; i < 20; ++i) {
            assert(vaultStatusChecks.elements[i] == address(0));
        }

        for (uint i = 0; i < vsc.length; ++i) {
            assert(keccak256(vaultStatuses[vsc[i].vault]) == keccak256(abi.encode(0)));
        }
    }

    function verifyVaultStatusChecks(VaultStatusCheck[] memory vsc) internal view {
        for (uint i = 0; i < vsc.length; ++i) {
            uint[] memory hooks = EulerVaultMock(vsc[i].vault).getHooksCalled();

            assert(hooks.length == vsc[i].hooks.length);

            if (hooks.length == 2) {
                if (hooks[0] == vsc[i].hooks[0]) {
                    assert(hooks[1] == vsc[i].hooks[1]);
                } else {
                    assert(hooks[0] == vsc[i].hooks[1]);
                    assert(hooks[1] == vsc[i].hooks[0]);
                }
            } else if (hooks.length == 1) {
                assert(hooks[0] == vsc[i].hooks[0]);
            } else {
                revert("unexpected number of hooks called");
            }
        }
    }

    function verifyAccountStatusChecks(AccountStatusCheck[] memory asc) internal {
        for (uint i = 0; i < asc.length; ++i) {
            address[] memory accounts = EulerVaultMock(asc[i].vault).getAccountStatusChecked();

            assert(accounts.length == asc[i].accounts.length);

            // copy the accounts to the helper array
            for (uint j = 0; j < accounts.length; ++j) {
                assert(helperArray.doAddElement(accounts[j]));
            }

            for (uint j = 0; j < asc[i].accounts.length; ++j) {
                assert(helperArray.doRemoveElement(asc[i].accounts[j]));
            }
        }
    }

    function performerConductorChecks(address account) internal {
        if (checksDeferred) return;

        address[] memory conductors = accountConductors[account].getArray();

        assert(conductors.length <= 1);

        if (conductors.length == 0) return;

        AccountStatusCheck[] memory asc = new AccountStatusCheck[](1);
        VaultStatusCheck[] memory vsc = new VaultStatusCheck[](0);

        asc[0].vault = conductors[0];
        asc[0].accounts = new address[](1);
        asc[0].accounts[0] = account;

        verifyTransientStorage(vsc);
        verifyAccountStatusChecks(asc);
    }

    function handlerEnablePerformer(address account, address vault) external {
        super.enablePerformer(account, vault);

        performerConductorChecks( account);   
    }

    function handlerDisablePerformer(address account, address vault) external {
        super.disablePerformer(account, vault);

        performerConductorChecks(account);
    }

    function handlerEnableConductor(address account, address vault) external {
        super.enableConductor(account, vault);

        performerConductorChecks(account);   
    }

    function handlerDisableConductor(address account, address vault) external {
        super.disableConductor(account, vault);

        performerConductorChecks(account);   
    }

    function handlerDeferChecks(bytes memory data, AccountStatusCheck[] memory asc, VaultStatusCheck[] memory vsc) public payable {
        super.deferChecks(data);

        verifyTransientStorage(vsc);
        verifyVaultStatusChecks(vsc);
        verifyAccountStatusChecks(asc);
    }

    function handlerBatchDispatch(EulerBatchItem[] calldata items, bool isSimulation, AccountStatusCheck[] memory asc, VaultStatusCheck[] memory vsc) public payable 
    returns (EulerBatchItemSimulationResult[] memory simulation) {
        simulation = super.batchDispatch(items, isSimulation);

        verifyTransientStorage(vsc);
        verifyVaultStatusChecks(vsc);
        verifyAccountStatusChecks(asc);
    }

    function handlerBatchDispatchSimulate(EulerBatchItem[] calldata items, AccountStatusCheck[] memory asc, VaultStatusCheck[] memory vsc) public payable 
    returns (EulerBatchItemSimulationResult[] memory simulation) {
        simulation = super.batchDispatchSimulate(items);

        verifyTransientStorage(vsc);
        verifyVaultStatusChecks(vsc);
        verifyAccountStatusChecks(asc);
    }

    function handlerExecute(address targetContract, address targetAccount, bytes calldata data) public payable
    returns (bool success, bytes memory result) {
        (success, result) = super.execute(targetContract, targetAccount, data);

        if (!checksDeferred && EulerRegistryMock(eulerVaultRegistry).isRegistered(targetContract)) {
            AccountStatusCheck[] memory asc = new AccountStatusCheck[](1);
            VaultStatusCheck[] memory vsc = new VaultStatusCheck[](1);

            asc[0].vault = targetContract;
            asc[0].accounts = new address[](1);
            asc[0].accounts[0] = targetAccount;

            vsc[0].vault = targetContract;
            vsc[0].hooks = new uint[](2);
            vsc[0].hooks[0] = 0;
            vsc[0].hooks[1] = 1;

            verifyTransientStorage(vsc);
            verifyVaultStatusChecks(vsc);
            verifyAccountStatusChecks(asc);
        }
    }

    function handlerForward(address targetContract, address targetAccount, bytes calldata data) public payable
    returns (bool success, bytes memory result) {
        (success, result) = super.forward(targetContract, targetAccount, data);

        if (!checksDeferred) {
            AccountStatusCheck[] memory asc = new AccountStatusCheck[](1);
            VaultStatusCheck[] memory vsc = new VaultStatusCheck[](1);

            asc[0].vault = targetContract;
            asc[0].accounts = new address[](1);
            asc[0].accounts[0] = targetAccount;

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

contract EulerOrchestratorTest is Test {
    address owner = makeAddr("owner");
    EulerOrchestratorHandler orchestrator;
    address registry;

    function samePrimaryAccount(address accountOne, address accountTwo) internal pure returns (bool) {
        return (uint160(accountOne) | 0xFF) == (uint160(accountTwo) | 0xFF);
    }

    function setUp() public {
        registry = address(new EulerRegistryMock());
        orchestrator = new EulerOrchestratorHandler(owner, registry);
    }

    function test_SetGovernorAdmin(address newOwner) public {
        assertEq(orchestrator.governorAdmin(), owner);

        vm.prank(owner);
        //vm.expectEmit(address(true, false, false, false, orchestrator));
        //emit EulerOrchestrator.GovernorAdminSet(newOwner);
        orchestrator.setGovernorAdmin(newOwner);

        assertEq(orchestrator.governorAdmin(),newOwner);
    }

    function test_SetGovernorAdmin_RevertIfNotGovernor(address newOwner, address notOwner) public {
        vm.assume(notOwner != owner);

        assertEq(orchestrator.governorAdmin(), owner);

        vm.prank(notOwner);
        vm.expectRevert(EulerOrchestrator.NotAuthorized.selector);
        orchestrator.setGovernorAdmin(newOwner);
    }

    function test_SetEulerVaultRegistry(address newRegistry) public {
        vm.assume(newRegistry != address(0));

        assertEq(orchestrator.eulerVaultRegistry(), registry);

        vm.prank(owner);
        //vm.expectEmit(address(true, false, false, false, orchestrator));
        //emit EulerOrchestrator.EulerVaultRegistrySet(newRegistry);
        orchestrator.setEulerVaultRegistry(newRegistry);

        assertEq(orchestrator.eulerVaultRegistry(), newRegistry);
    }

    function test_SetEulerVaultRegistry_RevertIfNotGovernor(address newRegistry, address notOwner) public {
        vm.assume(notOwner != owner && newRegistry != address(0));

        assertEq(orchestrator.eulerVaultRegistry(), registry);

        vm.prank(notOwner);
        vm.expectRevert(EulerOrchestrator.NotAuthorized.selector);
        orchestrator.setEulerVaultRegistry(newRegistry);
    }

    function test_SetEulerVaultRegistry_RevertIfZeroAddress() public {
        assertEq(orchestrator.eulerVaultRegistry(), registry);

        vm.prank(owner);
        vm.expectRevert(EulerOrchestrator.InvalidAddress.selector);
        orchestrator.setEulerVaultRegistry(address(0));
    }

    function test_SetAccountOperator(address alice, address operator) public {
        vm.assume(!samePrimaryAccount(alice, operator));

        for (uint i = 0; i < 256; ++i) {
            address account = address(uint160(uint160(alice) ^ i));

            assertFalse(orchestrator.accountOperators(account, operator));

            vm.prank(alice);
            //vm.expectEmit(address(true, true, false, true, orchestrator));
            //emit EulerOrchestrator.AccountOperatorSet(account, operator, true);
            orchestrator.setAccountOperator(account, operator, true);

            assertTrue(orchestrator.accountOperators(account, operator));

            vm.prank(alice);
            //vm.expectEmit(address(true, true, false, true, orchestrator));
            //emit EulerOrchestrator.AccountOperatorSet(account, operator, false);
            orchestrator.setAccountOperator(account, operator, false);

            assertFalse(orchestrator.accountOperators(account, operator));
        }
    }

    function test_SetAccountOperator_RevertIfSenderNotAuthorized(address alice, address operator) public {
        vm.assume(!samePrimaryAccount(alice, operator));

        address account = address(uint160(uint160(alice) ^ 256));

        assertFalse(orchestrator.accountOperators(account, operator));

        vm.prank(alice);
        vm.expectRevert(EulerOrchestrator.NotAuthorized.selector);
        orchestrator.setAccountOperator(account, operator, true);
    }

    function test_SetAccountOperator_RevertIfOperatorIsSenderSubAccount(address alice, uint8 subAccountId) public {
        address operator = address(uint160(uint160(alice) ^ subAccountId));

        assertFalse(orchestrator.accountOperators(alice, operator));

        vm.prank(alice);
        vm.expectRevert(EulerOrchestrator.InvalidAddress.selector);
        orchestrator.setAccountOperator(alice, operator, true);
    }

    function test_GetPerformers(address alice) public {
        orchestrator.setChecksDeferred(false);
        orchestrator.getPerformers(alice);
    }

    function test_GetPerformers_RevertIfChecksDeferred(address alice) public {
        orchestrator.setChecksDeferred(true);
        vm.expectRevert(EulerOrchestrator.DeferralViolation.selector);
        orchestrator.getPerformers(alice);
    }

    function test_IsPerformerEnabled(address alice, address vault) public {
        orchestrator.setChecksDeferred(false);
        orchestrator.isPerformerEnabled(alice, vault);
    }

    function test_IsPerformerEnabled_RevertIfChecksDeferred(address alice, address vault) public {
        orchestrator.setChecksDeferred(true);
        vm.expectRevert(EulerOrchestrator.DeferralViolation.selector);
        orchestrator.isPerformerEnabled(alice, vault);
    }

    function test_PerformersManagement(address alice, uint8 subAccountId, uint8 numberOfVaults, uint seed) public {
        vm.assume(numberOfVaults <= 20);
        vm.assume(seed > 1000);

        address account = address(uint160(uint160(alice) ^ subAccountId));

        // test performers management with use of an operator
        address msgSender = alice;
        if (seed % 2 == 0 && !samePrimaryAccount(account, address(uint160(seed)))) {
            msgSender = address(uint160(seed));
            vm.prank(alice);
            orchestrator.setAccountOperator(account, msgSender, true);
        }

        // enable a conductor to check if account status check works properly
        address conductor = address(new EulerVaultMock());
        if (seed % 3 == 0) {
            EulerRegistryMock(registry).setRegistered(conductor, true);

            vm.prank(alice);
            orchestrator.enableConductor(account, conductor);
        }

        // enabling performers
        for (uint i = 1; i <= numberOfVaults; ++i) {
            EulerVaultMock(conductor).reset();
            address[] memory performersPre = orchestrator.getPerformers(account);

            address vault = i % 5 == 0 
                ? performersPre[seed % performersPre.length]
                : address(new EulerVaultMock());

            EulerRegistryMock(registry).setRegistered(vault, true);
            bool alreadyEnabled = orchestrator.isPerformerEnabled(account, vault);

            assert((alreadyEnabled && i % 5 == 0) || (!alreadyEnabled && i % 5 != 0));

            vm.prank(msgSender);
            orchestrator.handlerEnablePerformer(account, vault);
            
            address[] memory performersPost = orchestrator.getPerformers(account);
            
            if (alreadyEnabled) {
                assertEq(performersPost.length, performersPre.length);
            } else {
                assertEq(performersPost.length, performersPre.length + 1);
                assertEq(performersPost[performersPost.length - 1], vault);
            }

            for (uint j = 0; j < performersPre.length; ++j) {
                assertEq(performersPre[j], performersPost[j]);
            }
        }

        // disabling performers
        while (orchestrator.getPerformers(account).length > 0) {
            EulerVaultMock(conductor).reset();
            address[] memory performersPre = orchestrator.getPerformers(account);
            address vault = performersPre[seed % performersPre.length];

            vm.prank(msgSender);
            orchestrator.handlerDisablePerformer(account, vault);

            address[] memory performersPost = orchestrator.getPerformers(account);

            assertEq(performersPost.length, performersPre.length - 1);

            for (uint j = 0; j < performersPost.length; ++j) {
                assertNotEq(performersPost[j], vault);
            }
        }
    }

    function test_PerformersManagement_RevertIfNotOwnerAndNotOperator(address alice, address bob) public {
        vm.assume(!samePrimaryAccount(alice, bob));

        address vault = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(vault, true);

        vm.prank(alice);
        vm.expectRevert(EulerOrchestrator.NotAuthorized.selector);
        orchestrator.handlerEnablePerformer(bob, vault);

        vm.prank(alice);
        vm.expectRevert(EulerOrchestrator.NotAuthorized.selector);
        orchestrator.handlerDisablePerformer(bob, vault);


        vm.prank(bob);
        orchestrator.setAccountOperator(bob, alice, true);

        vm.prank(alice);
        orchestrator.handlerEnablePerformer(bob, vault);

        vm.prank(alice);
        orchestrator.handlerDisablePerformer(bob, vault);
    }

    function test_PerformersManagement_RevertIfVaultNotRegistered(address alice) public {
        address vault = address(new EulerVaultMock());

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(EulerOrchestrator.VaultNotRegistered.selector, vault));
        orchestrator.handlerEnablePerformer(alice, vault);

        vm.prank(alice);
        // does not revert. because only registered performers can be enabled it doesn't check for registration here
        orchestrator.handlerDisablePerformer(alice, vault);


        EulerRegistryMock(registry).setRegistered(vault, true);

        vm.prank(alice);
        orchestrator.handlerEnablePerformer(alice, vault);


        vm.prank(alice);
        orchestrator.handlerDisablePerformer(alice, vault);
    }

    function test_PerformersManagement_RevertIfAccountStatusViolated(address alice) public {
        address vault = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(vault, true);

        address conductor = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(conductor, true);

        vm.prank(alice);
        orchestrator.enableConductor(alice, conductor);
        EulerVaultMock(conductor).reset();

        EulerVaultMock(conductor).setAccountStatusState(1); // account status is violated

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(EulerOrchestrator.AccountStatusViolation.selector, alice));
        orchestrator.handlerEnablePerformer(alice, vault);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(EulerOrchestrator.AccountStatusViolation.selector, alice));
        orchestrator.handlerDisablePerformer(alice, vault);


        EulerVaultMock(conductor).setAccountStatusState(0); // account status is NOT violated
        
        vm.prank(alice);
        orchestrator.handlerEnablePerformer(alice, vault);
        EulerVaultMock(conductor).reset();  // reset so that the account status check verification succeeds

        vm.prank(alice);
        orchestrator.handlerDisablePerformer(alice, vault);
    }

    function test_GetConductors(address alice) public {
        orchestrator.setChecksDeferred(false);
        orchestrator.getConductors(alice);
    }

    function test_GetConductors_RevertIfChecksDeferred(address alice) public {
        orchestrator.setChecksDeferred(true);
        vm.expectRevert(EulerOrchestrator.DeferralViolation.selector);
        orchestrator.getConductors(alice);
    }

    function test_IsConductorEnabled(address alice) public {
        address vault = address(new EulerVaultMock());
        orchestrator.setChecksDeferred(false);
        orchestrator.isConductorEnabled(alice, vault);

        // even though checks are deferred, the function succeeds if called by the vault asking if vault enabled
        // as a conductor
        orchestrator.setChecksDeferred(true);
        EulerVaultMock(vault).call(
            address(orchestrator),
            abi.encodeWithSelector(EulerOrchestrator.isConductorEnabled.selector, alice, vault)
        );
    }

    function test_IsConductorEnabled_RevertIfChecksDeferredAndMsgSenderNotVault(address alice, address vault) public {
        vm.assume(address(this) != vault);

        orchestrator.setChecksDeferred(true);
        vm.expectRevert(EulerOrchestrator.DeferralViolation.selector);
        orchestrator.isConductorEnabled(alice, vault);
    }

    function test_ConductorsManagement(address alice, uint8 subAccountId, uint seed) public {
        vm.assume(seed > 1000);

        address account = address(uint160(uint160(alice) ^ subAccountId));

        // test conductors management with use of an operator
        address msgSender = alice;
        if (seed % 2 == 0 && !samePrimaryAccount(account, address(uint160(seed)))) {
            msgSender = address(uint160(seed));
            vm.prank(alice);
            orchestrator.setAccountOperator(account, msgSender, true);
        }

        // enabling conductor
        address vault = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(vault, true);

        assertFalse(orchestrator.isConductorEnabled(account, vault));
        address[] memory conductorsPre = orchestrator.getConductors(account);

        vm.prank(msgSender);
        orchestrator.handlerEnableConductor(account, vault);
        
        address[] memory conductorsPost = orchestrator.getConductors(account);
        
        assertEq(conductorsPost.length, conductorsPre.length + 1);
        assertEq(conductorsPost[conductorsPost.length - 1], vault);
        assertTrue(orchestrator.isConductorEnabled(account, vault));

        // enabling the same conductor again should succeed (duplicate will not be added)
        EulerVaultMock(vault).reset();
        assertTrue(orchestrator.isConductorEnabled(account, vault));
        conductorsPre = orchestrator.getConductors(account);

        vm.prank(msgSender);
        orchestrator.handlerEnableConductor(account, vault);
        
        conductorsPost = orchestrator.getConductors(account);
        
        assertEq(conductorsPost.length, conductorsPre.length);
        assertEq(conductorsPost[0], conductorsPre[0]);
        assertTrue(orchestrator.isConductorEnabled(account, vault));
        
        // trying to enable second conductor will throw on the account status check if checks are not deferred
        address otherVault = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(otherVault, true);

        vm.prank(msgSender);
        vm.expectRevert(abi.encodeWithSelector(EulerOrchestrator.ConductorViolation.selector, account));
        orchestrator.handlerEnableConductor(account, otherVault);

        // only the conductor vault can disable itself
        EulerVaultMock(vault).reset();
        assertTrue(orchestrator.isConductorEnabled(account, vault));
        conductorsPre = orchestrator.getConductors(account);

        vm.prank(msgSender);
        EulerVaultMock(vault).call(
            address(orchestrator),
            abi.encodeWithSelector(EulerOrchestratorHandler.handlerDisableConductor.selector, account, vault)
        );
        
        conductorsPost = orchestrator.getConductors(account);
        
        assertEq(conductorsPost.length, conductorsPre.length - 1);
        assertEq(conductorsPost.length, 0);
        assertFalse(orchestrator.isConductorEnabled(account, vault));
    }

    function test_EnableConductor_RevertIfNotOwnerAndNotOperator(address alice, address bob) public {
        vm.assume(!samePrimaryAccount(alice, bob));

        address vault = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(vault, true);

        vm.prank(alice);
        vm.expectRevert(EulerOrchestrator.NotAuthorized.selector);
        orchestrator.handlerEnableConductor(bob, vault);


        vm.prank(bob);
        orchestrator.setAccountOperator(bob, alice, true);

        vm.prank(alice);
        orchestrator.handlerEnableConductor(bob, vault);
    }

    function test_DisableConductor_RevertIfMsgSenderNotConductor(address alice, address bob) public {
        vm.assume(!samePrimaryAccount(alice, bob));

        address vault = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(vault, true);

        vm.assume(alice != vault);

        vm.prank(alice);
        vm.expectRevert(EulerOrchestrator.NotAuthorized.selector);
        orchestrator.handlerDisableConductor(bob, vault);

        vm.prank(bob);
        orchestrator.setAccountOperator(bob, alice, true);

        vm.prank(alice);
        vm.expectRevert(EulerOrchestrator.NotAuthorized.selector);  // although operator, conductor msg.sender is expected
        orchestrator.handlerDisableConductor(bob, vault);

        vm.prank(alice);
        EulerVaultMock(vault).call(
            address(orchestrator),
            abi.encodeWithSelector(EulerOrchestratorHandler.handlerDisableConductor.selector, bob, vault)
        );
    }

    function test_ConductorsManagement_RevertIfVaultNotRegistered(address alice) public {
        address vault = address(new EulerVaultMock());

        vm.assume(alice != vault);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(EulerOrchestrator.VaultNotRegistered.selector, vault));
        orchestrator.handlerEnableConductor(alice, vault);

        vm.prank(alice);
        vm.expectRevert(EulerOrchestrator.NotAuthorized.selector);
        orchestrator.handlerDisableConductor(alice, vault);


        EulerRegistryMock(registry).setRegistered(vault, true);

        vm.prank(alice);
        orchestrator.handlerEnableConductor(alice,vault );

        //EulerVaultMock(vault).reset(); // not necessary as there's no conductor to perform the account status check
        vm.prank(alice);
        EulerVaultMock(vault).call(
            address(orchestrator),
            abi.encodeWithSelector(EulerOrchestratorHandler.handlerDisableConductor.selector, alice, vault)
        );
    }

    function test_ConductorsManagement_RevertIfAccountStatusViolated(address alice) public {
        address vault = address(new EulerVaultMock());
        EulerRegistryMock(registry).setRegistered(vault, true);

        EulerVaultMock(vault).setAccountStatusState(1); // account status is violated

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(EulerOrchestrator.AccountStatusViolation.selector, alice));
        orchestrator.handlerEnableConductor(alice, vault);

        vm.prank(alice);
        // succeeds as there's no conductor to perform the account status check
        EulerVaultMock(vault).call(
            address(orchestrator),
            abi.encodeWithSelector(EulerOrchestratorHandler.handlerDisableConductor.selector, alice, vault)
        );

        EulerVaultMock(vault).reset();  // account status is NOT violated
        
        vm.prank(alice);
        orchestrator.handlerEnablePerformer(alice, vault);
    }
}
