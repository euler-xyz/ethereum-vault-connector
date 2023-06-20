// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/EulerConductor.sol";
import "../src/Types.sol";
import "../src/Array.sol";

contract EulerRegistryMock is IEulerVaultRegistry {
    function isRegistered(address vault) external pure returns (bool) {
        return uint160(vault) % 7 == 0 ? false : true;
    }
}

contract EulerVaultMock is IEulerVault {
    function checkAccountStatus(address, address[] memory) external pure returns (bool) {
        return true;
    }

    function assetStatusHook(bool, bytes memory data) external pure returns (bytes memory result) {
        return data;
    }
    
    fallback(bytes calldata) external payable returns (bytes memory) {
        return "";
    }

    receive() external payable {}
}

contract EulerConductorHandler is EulerConductor, Test {
    using Array for ArrayStorage;
    
    address vaultMock;
    address[] public touchedAccounts;

    function getTouchedAccounts() external view returns (address[] memory) {
        return touchedAccounts;
    }

    function setup(address account, address vault) internal {
        touchedAccounts.push(account);
        vm.etch(vault, vaultMock.code);
        accountOperators[account][msg.sender] = true;
    }

    constructor(address admin, address registry) EulerConductor(admin, registry) {
        vaultMock = address(new EulerVaultMock());
    }

    function setGovernorAdmin(address newGovernorAdmin) public payable override {
        governorAdmin = msg.sender;
        newGovernorAdmin = msg.sender;
        super.setGovernorAdmin(newGovernorAdmin);
    }

    function setEulerVaultRegistry(address newEulerVaultRegistry) public payable override {
        governorAdmin = msg.sender;
        newEulerVaultRegistry = eulerVaultRegistry;
        super.setEulerVaultRegistry(newEulerVaultRegistry);
    }

    function setAccountOperator(address account, address operator, bool isAuthorized) public payable override {
        if ((uint160(msg.sender) | 0xFF) == (uint160(operator) | 0xFF)) return;
        account = msg.sender;
        super.setAccountOperator(account, operator, isAuthorized);
    }

    function enableCollateral(address account, address vault) public payable override {
        if (uint160(vault) <= 10) return;
        if (vault == address(this)) return;
        if (vault == eulerVaultRegistry) return;
        setup(account, vault);
        super.enableCollateral(account, vault);
    }

    function disableCollateral(address account, address vault) public payable override {
        if (uint160(vault) <= 10) return;
        if (vault == address(this)) return;
        if (vault == eulerVaultRegistry) return;
        setup(account, vault);
        super.disableCollateral(account, vault);
    }

    function enableController(address account, address vault) public payable override {
        if (uint160(vault) <= 10) return;
        if (vault == address(this)) return;
        if (vault == eulerVaultRegistry) return;
        setup(account, vault);
        super.enableCollateral(account, vault);
    }

    function disableController(address account, address vault) public payable override {
        vault = msg.sender;
        if (uint160(vault) <= 10) return;
        if (vault == address(this)) return;
        if (vault == eulerVaultRegistry) return;
        setup(account, vault);
        super.disableController(account, vault);
    }

    function batch(EulerBatchItem[] calldata items) public payable override {
        if (items.length > 10) return;
        
        for (uint i = 0; i < items.length && i < 10; i++) {
            if (uint160(items[i].msgValue) > type(uint128).max) return;
            if (uint160(items[i].targetContract) <= 10) return;
            if (items[i].targetContract == address(this)) return;
            if (items[i].targetContract == eulerVaultRegistry) return;
        }

        vm.deal(address(this), type(uint).max);
        super.batch(items);
    }

    function batchRevert(EulerBatchItem[] calldata) public payable override
    returns (EulerResult[] memory batchItemsResult, EulerResult[] memory accountsStatusResult, EulerResult[] memory vaultsStatusResult) {
        EulerResult[] memory x;
        return (x, x, x);
    }

    function batchSimulation(EulerBatchItem[] calldata) public payable override
    returns (EulerResult[] memory batchItemsResult, EulerResult[] memory accountsStatusResult, EulerResult[] memory vaultsStatusResult) {
        EulerResult[] memory x;
        return (x, x, x);
    }

    function executeInternal(address targetContract, address onBehalfOfAccount, uint msgValue, bytes calldata data) internal override
    returns (bool success, bytes memory result) {
        if (uint160(targetContract) <= 10) return (true, "");
        if (targetContract == address(this)) return (true, "");
        if (targetContract == eulerVaultRegistry) return (true, "");
        setup(onBehalfOfAccount, targetContract);
        return super.executeInternal(targetContract, onBehalfOfAccount, msgValue, data);
    }

    function forwardInternal(address targetContract, address onBehalfOfAccount, uint msgValue, bytes calldata data) internal override
    returns (bool success, bytes memory result) {
        if (uint160(msg.sender) <= 10) return (true, "");
        if (msg.sender == address(this)) return (true, "");
        if (msg.sender == eulerVaultRegistry) return (true, "");
        if (uint160(targetContract) <= 10) return (true, "");
        if (targetContract == address(this)) return (true, "");
        if (targetContract == eulerVaultRegistry) return (true, "");
        setup(onBehalfOfAccount, msg.sender);
        setup(onBehalfOfAccount, targetContract);
        accountControllers[onBehalfOfAccount].doAddElement(msg.sender);
        accountCollaterals[onBehalfOfAccount].doAddElement(targetContract);
        return super.forwardInternal(targetContract, onBehalfOfAccount, msgValue, data);
    }

    function requireAccountsStatusCheck(address[] calldata accounts) public override {
        if (accounts.length > 10) return;
        super.requireAccountsStatusCheck(accounts);
    }

    function exposeAccountCollaterals(address account) external view returns (ArrayStorage memory) {
        return accountControllers[account];
    }

    function exposeAccountControllers(address account) external view returns (ArrayStorage memory) {
        return accountControllers[account];
    }

    function exposeTransientStorage() external view returns (ArrayStorage memory, ArrayStorage memory) {
        return (accountStatusChecks, vaultStatusChecks);
    }
}

contract EulerConductorTest is Test {
    address governor = makeAddr("governor");
    address registry;
    EulerConductorHandler conductor;

    function setUp() public {
        registry = address(new EulerRegistryMock());
        conductor = new EulerConductorHandler(governor, registry);

        targetContract(address(conductor));
    }

    function invariant_context() external {
        (bool checksDeferred, address account) = conductor.getExecutionContext();
        assertFalse(checksDeferred);
        assertTrue(account == address(0));
    }

    function invariant_transientStorage() external {     
        (
            Types.ArrayStorage memory accountStatusChecks, 
            Types.ArrayStorage memory vaultStatusChecks
        ) = conductor.exposeTransientStorage();

        assertTrue(accountStatusChecks.numElements == 0);
        assertTrue(accountStatusChecks.firstElement == address(0));
        assertTrue(vaultStatusChecks.numElements == 0);
        assertTrue(vaultStatusChecks.firstElement == address(0));
    }

    function invariant_controllers() external {
        address[] memory touchedAccounts = conductor.getTouchedAccounts();
        for (uint i = 0; i < touchedAccounts.length; i++) {
            Types.ArrayStorage memory accountControllers = conductor.exposeAccountControllers(touchedAccounts[i]);
            address[] memory accountControllersArray = conductor.getControllers(touchedAccounts[i]);
        
            assertTrue(accountControllers.numElements == 0 || accountControllers.numElements == 1);
            assertTrue(
                (accountControllers.numElements == 0 && accountControllers.firstElement == address(0)) ||
                (accountControllers.numElements == 1 && accountControllers.firstElement != address(0))
            );

            for (uint j = 1; j < accountControllersArray.length; j++) {
                assertTrue(accountControllersArray[j] == address(0));
            }
        }
    }

    function invariant_collaterals() external {
        address[] memory touchedAccounts = conductor.getTouchedAccounts();
        for (uint i = 0; i < touchedAccounts.length; i++) {
            Types.ArrayStorage memory accountCollaterals = conductor.exposeAccountCollaterals(touchedAccounts[i]);
            address[] memory accountCollateralsArray = conductor.getCollaterals(touchedAccounts[i]);

            assertTrue(accountCollaterals.numElements <= 10);
            assertTrue(
                (accountCollaterals.numElements == 0 && accountCollaterals.firstElement == address(0)) ||
                (accountCollaterals.numElements == 1 && accountCollaterals.firstElement != address(0))
            );

            for (uint j = 0; j < accountCollateralsArray.length; j++) {
                assertTrue(accountCollateralsArray[j] != address(0));
            }

            // verify that none entry is duplicated
            for (uint j = 1; j < accountCollateralsArray.length; j++) {
                for (uint k = 0; k < j; k++) {
                    assertTrue(accountCollateralsArray[j] != accountCollateralsArray[k]);
                }
            }
        }
    }
}
