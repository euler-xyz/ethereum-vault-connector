// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/CreditVaultProtocol.sol";
import "../src/Types.sol";
import "../src/Set.sol";

contract RegistryMock is ICreditVaultRegistry {
    function isRegistered(address vault) external pure returns (bool) {
        return vault == address(0) ? false : true;
    }
}

contract VaultMock is ICreditVault {
    ICVP public immutable cvp;

    constructor(ICVP _cvp) {
        cvp = _cvp;
    }

    function disableController(address account) public override {}

    function checkAccountStatus(address, address[] memory) external pure override returns (bool, bytes memory) {
        return (true, "");
    }

    function checkVaultStatus() external pure override returns (bool, bytes memory) {
        return (true, "");
    }
    
    fallback(bytes calldata) external payable returns (bytes memory) {
        cvp.requireAccountStatusCheck(address(0));
        cvp.requireVaultStatusCheck(address(this));
        return "";
    }

    receive() external payable {}
}

contract CreditVaultProtocolHandler is CreditVaultProtocol, Test {
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

    constructor(address admin, address registry) CreditVaultProtocol(admin, registry) {
        vaultMock = address(new VaultMock(ICVP(address(this))));
    }

    function setGovernorAdmin(address newGovernorAdmin) public payable override {
        governorAdmin = msg.sender;
        newGovernorAdmin = msg.sender;
        super.setGovernorAdmin(newGovernorAdmin);
    }

    function setVaultRegistry(address newVaultRegistry) public payable override {
        governorAdmin = msg.sender;
        newVaultRegistry = vaultRegistry;
        super.setVaultRegistry(newVaultRegistry);
    }

    function setAccountOperator(address account, address operator, bool isAuthorized) public payable override {
        if ((uint160(msg.sender) | 0xFF) == (uint160(operator) | 0xFF)) return;
        account = msg.sender;
        super.setAccountOperator(account, operator, isAuthorized);
    }

    function enableCollateral(address account, address vault) public payable override {
        if (uint160(vault) <= 10) return;
        if (vault == address(this)) return;
        if (vault == vaultRegistry) return;
        setup(account, vault);
        super.enableCollateral(account, vault);
    }

    function disableCollateral(address account, address vault) public payable override {
        if (uint160(vault) <= 10) return;
        if (vault == address(this)) return;
        if (vault == vaultRegistry) return;
        setup(account, vault);
        super.disableCollateral(account, vault);
    }

    function enableController(address account, address vault) public payable override {
        if (uint160(vault) <= 10) return;
        if (vault == address(this)) return;
        if (vault == vaultRegistry) return;
        setup(account, vault);
        super.enableCollateral(account, vault);
    }

    function disableController(address account, address vault) public payable override {
        vault = msg.sender;
        if (uint160(vault) <= 10) return;
        if (vault == address(this)) return;
        if (vault == vaultRegistry) return;
        setup(account, vault);
        super.disableController(account, vault);
    }

    function batch(BatchItem[] calldata items) public payable override {
        if (items.length > 10) return;
        
        for (uint i = 0; i < items.length && i < 10; i++) {
            if (uint160(items[i].msgValue) > type(uint128).max) return;
            if (uint160(items[i].targetContract) <= 10) return;
            if (items[i].targetContract == address(this)) return;
            if (items[i].targetContract == vaultRegistry) return;
        }

        vm.deal(address(this), type(uint).max);
        super.batch(items);
    }

    function batchRevert(BatchItem[] calldata) public payable override
    returns (BatchResult[] memory batchItemsResult, BatchResult[] memory accountsStatusResult, BatchResult[] memory vaultsStatusResult) {
        BatchResult[] memory x;
        return (x, x, x);
    }

    function batchSimulation(BatchItem[] calldata) public payable override
    returns (BatchResult[] memory batchItemsResult, BatchResult[] memory accountsStatusResult, BatchResult[] memory vaultsStatusResult) {
        BatchResult[] memory x;
        return (x, x, x);
    }

    function callInternal(address targetContract, address onBehalfOfAccount, uint msgValue, bytes calldata data) internal override
    returns (bool success, bytes memory result) {
        if (uint160(targetContract) <= 10) return (true, "");
        if (targetContract == address(this)) return (true, "");
        if (targetContract == vaultRegistry) return (true, "");
        if (onBehalfOfAccount == address(0)) onBehalfOfAccount = msg.sender;
        setup(onBehalfOfAccount, targetContract);
        return super.callInternal(targetContract, onBehalfOfAccount, msgValue, data);
    }

    function callFromControllerToCollateralInternal(address targetContract, address onBehalfOfAccount, uint msgValue, bytes calldata data) internal override
    returns (bool success, bytes memory result) {
        if (uint160(msg.sender) <= 10) return (true, "");
        if (msg.sender == address(this)) return (true, "");
        if (msg.sender == vaultRegistry) return (true, "");
        if (uint160(targetContract) <= 10) return (true, "");
        if (targetContract == address(this)) return (true, "");
        if (targetContract == vaultRegistry) return (true, "");
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

contract CreditVaultProtocolInvariants is Test {
    address governor = makeAddr("governor");
    address registry;
    CreditVaultProtocolHandler cvp;

    function setUp() public {
        registry = address(new RegistryMock());
        vm.assume(governor != address(0));
        vm.assume(registry != address(0));

        cvp = new CreditVaultProtocolHandler(governor, registry);

        targetContract(address(cvp));
    }

    function invariant_context() external {
        (bool checksDeferred, address account) = cvp.getExecutionContext();
        assertFalse(checksDeferred);
        assertTrue(account == address(0));
    }

    function invariant_transientStorage() external {     
        (
            Types.SetStorage memory accountStatusChecks, 
            Types.SetStorage memory vaultStatusChecks
        ) = cvp.exposeTransientStorage();

        assertTrue(accountStatusChecks.numElements == 0);
        assertTrue(accountStatusChecks.firstElement == address(0));
        assertTrue(vaultStatusChecks.numElements == 0);
        assertTrue(vaultStatusChecks.firstElement == address(0));
    }

    function invariant_controllers() external {
        address[] memory touchedAccounts = cvp.getTouchedAccounts();
        for (uint i = 0; i < touchedAccounts.length; i++) {
            Types.SetStorage memory accountControllers = cvp.exposeAccountControllers(touchedAccounts[i]);
            address[] memory accountControllersArray = cvp.getControllers(touchedAccounts[i]);
        
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
        address[] memory touchedAccounts = cvp.getTouchedAccounts();
        for (uint i = 0; i < touchedAccounts.length; i++) {
            Types.SetStorage memory accountCollaterals = cvp.exposeAccountCollaterals(touchedAccounts[i]);
            address[] memory accountCollateralsArray = cvp.getCollaterals(touchedAccounts[i]);

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