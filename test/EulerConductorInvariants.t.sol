// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/EulerConductor.sol";
import "../src/Types.sol";
import "../src/Set.sol";

contract EulerRegistryMock is IEulerVaultRegistry {
    function isRegistered(address vault) external pure returns (bool) {
        return vault == address(0) ? false : true;
    }
}

contract EulerVaultMock is IEulerVault {
    address public immutable eulerConductor;

    constructor(address _eulerConductor) {
        eulerConductor = _eulerConductor;
    }

    function disableController(address account) public override {}

    function checkAccountStatus(address, address[] memory) external pure override returns (bool, bytes memory) {
        return (true, "");
    }

    function checkVaultStatus() external pure override returns (bool, bytes memory) {
        return (true, "");
    }
    
    fallback(bytes calldata) external payable returns (bytes memory) {
        IEulerConductor(eulerConductor).requireAccountStatusCheck(address(0));
        IEulerConductor(eulerConductor).requireVaultStatusCheck(address(this));
        return "";
    }

    receive() external payable {}
}

contract EulerConductorHandler is EulerConductor, Test {
    using Set for SetStorage;
    
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
        vaultMock = address(new EulerVaultMock(address(this)));
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

    function callInternal(address targetContract, address onBehalfOfAccount, uint msgValue, bytes calldata data) internal override
    returns (bool success, bytes memory result) {
        if (uint160(targetContract) <= 10) return (true, "");
        if (targetContract == address(this)) return (true, "");
        if (targetContract == eulerVaultRegistry) return (true, "");
        if (onBehalfOfAccount == address(0)) onBehalfOfAccount = msg.sender;
        setup(onBehalfOfAccount, targetContract);
        return super.callInternal(targetContract, onBehalfOfAccount, msgValue, data);
    }

    function callFromControllerToCollateralInternal(address targetContract, address onBehalfOfAccount, uint msgValue, bytes calldata data) internal override
    returns (bool success, bytes memory result) {
        if (uint160(msg.sender) <= 10) return (true, "");
        if (msg.sender == address(this)) return (true, "");
        if (msg.sender == eulerVaultRegistry) return (true, "");
        if (uint160(targetContract) <= 10) return (true, "");
        if (targetContract == address(this)) return (true, "");
        if (targetContract == eulerVaultRegistry) return (true, "");
        if (onBehalfOfAccount == address(0)) onBehalfOfAccount = msg.sender;
        setup(onBehalfOfAccount, msg.sender);
        setup(onBehalfOfAccount, targetContract);
        accountControllers[onBehalfOfAccount].insert(msg.sender);
        accountCollaterals[onBehalfOfAccount].insert(targetContract);
        return super.callFromControllerToCollateralInternal(targetContract, onBehalfOfAccount, msgValue, data);
    }

    function requireAccountsStatusCheck(address[] calldata accounts) public override {
        if (accounts.length > 10) return;
        super.requireAccountsStatusCheck(accounts);
    }

    function requireVaultStatusCheck(address vault) public override {
        vault = msg.sender;
        super.requireVaultStatusCheck(vault);
    }

    function exposeAccountCollaterals(address account) external view returns (SetStorage memory) {
        return accountControllers[account];
    }

    function exposeAccountControllers(address account) external view returns (SetStorage memory) {
        return accountControllers[account];
    }

    function exposeTransientStorage() external view returns (SetStorage memory, SetStorage memory) {
        return (accountStatusChecks, vaultStatusChecks);
    }
}

contract EulerConductorInvariants is Test {
    address governor = makeAddr("governor");
    address registry;
    EulerConductorHandler conductor;

    function setUp() public {
        registry = address(new EulerRegistryMock());
        vm.assume(governor != address(0));
        vm.assume(registry != address(0));

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
            Types.SetStorage memory accountStatusChecks, 
            Types.SetStorage memory vaultStatusChecks
        ) = conductor.exposeTransientStorage();

        assertTrue(accountStatusChecks.numElements == 0);
        assertTrue(accountStatusChecks.firstElement == address(0));
        assertTrue(vaultStatusChecks.numElements == 0);
        assertTrue(vaultStatusChecks.firstElement == address(0));
    }

    function invariant_controllers() external {
        address[] memory touchedAccounts = conductor.getTouchedAccounts();
        for (uint i = 0; i < touchedAccounts.length; i++) {
            Types.SetStorage memory accountControllers = conductor.exposeAccountControllers(touchedAccounts[i]);
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
            Types.SetStorage memory accountCollaterals = conductor.exposeAccountCollaterals(touchedAccounts[i]);
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
