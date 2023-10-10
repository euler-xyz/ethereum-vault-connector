// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../src/interfaces/IERC1271.sol";
import "../cvc/CreditVaultConnectorScribble.sol";

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

contract SignerMock {
    function isValidSignature(
        bytes32,
        bytes memory
    ) external pure returns (bytes4 magicValue) {
        return IERC1271.isValidSignature.selector;
    }
}

contract CreditVaultConnectorHandler is CreditVaultConnectorScribble, Test {
    using Set for SetStorage;

    address internal vaultMock;
    address internal signerMock;
    address[] public touchedAccounts;

    constructor() {
        vaultMock = address(new VaultMock(ICVC(address(this))));
        signerMock = address(new SignerMock());
    }

    function getTouchedAccounts() external view returns (address[] memory) {
        return touchedAccounts;
    }

    function setup(address account, address vault) internal {
        touchedAccounts.push(account);
        operatorLookup[account][msg.sender] = block.timestamp;
        vm.etch(vault, vaultMock.code);
    }

    function setNonce(
        address account,
        uint nonceNamespace,
        uint nonce
    ) public payable override {
        account = msg.sender;
        setAccountOwnerInternal(account, msg.sender);
        nonce =
            nonceLookup[getAddressPrefixInternal(account)][nonceNamespace] +
            1;
        super.setNonce(account, nonceNamespace, nonce);
    }

    function setAccountOperator(
        address account,
        address operator,
        uint expiryTimestamp
    ) public payable override {
        if (operator == address(0) || operator == address(this)) return;
        if (haveCommonOwnerInternal(msg.sender, operator)) return;
        account = msg.sender;
        setAccountOwnerInternal(account, msg.sender);
        super.setAccountOperator(account, operator, expiryTimestamp);
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
        if (onBehalfOfAccount == address(0)) return (true, "");
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
        if (onBehalfOfAccount == address(0)) return (true, "");
        if (uint160(targetContract) <= 10) return (true, "");
        if (targetContract == address(this)) return (true, "");

        setup(onBehalfOfAccount, msg.sender);
        accountCollaterals[onBehalfOfAccount].insert(targetContract);

        uint8 numElementsCache = accountControllers[onBehalfOfAccount]
            .numElements;
        address firstElementCache = accountControllers[onBehalfOfAccount]
            .firstElement;
        accountControllers[onBehalfOfAccount].numElements = 1;
        accountControllers[onBehalfOfAccount].firstElement = msg.sender;

        (success, result) = super.impersonate(
            targetContract,
            onBehalfOfAccount,
            data
        );

        accountControllers[onBehalfOfAccount].numElements = numElementsCache;
        accountControllers[onBehalfOfAccount].firstElement = firstElementCache;
    }

    function permit(
        address signer,
        uint nonceNamespace,
        uint nonce,
        uint deadline,
        bytes calldata data,
        bytes calldata signature
    ) public payable override {
        if (uint160(signer) <= 10) return;
        if (data.length == 0) return;
        vm.etch(signer, signerMock.code);
        nonce = nonceLookup[getAddressPrefixInternal(signer)][nonceNamespace] + 1;
        deadline = block.timestamp;
        super.permit(signer, nonceNamespace, nonce, deadline, data, signature);
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

        uint8 numElementsCache = accountControllers[account].numElements;
        address firstElementCache = accountControllers[account].firstElement;
        accountControllers[account].numElements = 1;
        accountControllers[account].firstElement = msg.sender;

        super.forgiveAccountStatusCheck(account);

        accountControllers[account].numElements = numElementsCache;
        accountControllers[account].firstElement = firstElementCache;
    }

    function forgiveAccountsStatusCheck(
        address[] calldata accounts
    ) public payable override {
        if (msg.sender == address(0)) return;
        if (accounts.length > Set.MAX_ELEMENTS) return;

        uint8[] memory numElementsCache = new uint8[](accounts.length);
        address[] memory firstElementCache = new address[](accounts.length);
        for (uint i = 0; i < accounts.length; i++) {
            address account = accounts[i];
            numElementsCache[i] = accountControllers[account].numElements;
            firstElementCache[i] = accountControllers[account].firstElement;
            accountControllers[account].numElements = 1;
            accountControllers[account].firstElement = msg.sender;
        }

        super.forgiveAccountsStatusCheck(accounts);

        for (uint i = accounts.length; i > 0; i--) {
            address account = accounts[i - 1];
            accountControllers[account].numElements = numElementsCache[i - 1];
            accountControllers[account].firstElement = firstElementCache[i - 1];
        }
    }

    function requireAccountStatusCheckInternal(address) internal pure override {
        return;
    }

    function requireVaultStatusCheckInternal(address) internal pure override {
        return;
    }

    fallback() external payable {}

    function exposeAccountCollaterals(
        address account
    ) external view returns (uint8, address[] memory) {
        address[] memory result = new address[](Set.MAX_ELEMENTS);

        for (uint i = 0; i < Set.MAX_ELEMENTS; i++) {
            if (i == 0) {
                result[i] = accountCollaterals[account].firstElement;
            } else {
                result[i] = accountCollaterals[account].elements[i].value;
            }
        }
        return (accountCollaterals[account].numElements, result);
    }

    function exposeAccountControllers(
        address account
    ) external view returns (uint8, address[] memory) {
        address[] memory result = new address[](Set.MAX_ELEMENTS);

        for (uint i = 0; i < Set.MAX_ELEMENTS; i++) {
            if (i == 0) {
                result[i] = accountControllers[account].firstElement;
            } else {
                result[i] = accountControllers[account].elements[i].value;
            }
        }
        return (accountControllers[account].numElements, result);
    }

    function exposeAccountAndVaultStatusCheck()
        external
        view
        returns (uint8, address[] memory, uint8, address[] memory)
    {
        address[] memory result1 = new address[](Set.MAX_ELEMENTS);
        address[] memory result2 = new address[](Set.MAX_ELEMENTS);

        for (uint i = 0; i < Set.MAX_ELEMENTS; i++) {
            if (i == 0) {
                result1[i] = accountStatusChecks.firstElement;
                result2[i] = vaultStatusChecks.firstElement;
            } else {
                result1[i] = accountStatusChecks.elements[i].value;
                result2[i] = vaultStatusChecks.elements[i].value;
            }
        }
        return (
            accountStatusChecks.numElements,
            result1,
            vaultStatusChecks.numElements,
            result2
        );
    }
}

contract CreditVaultConnectorInvariants is Test {
    CreditVaultConnectorHandler internal cvc;

    function setUp() public {
        cvc = new CreditVaultConnectorHandler();

        targetContract(address(cvc));
    }

    function invariant_executionContext() external {
        (address onBehalfOfAccount, bool controllerEnabled) = cvc
            .getExecutionContext(address(this));

        assertEq(onBehalfOfAccount, address(0));
        assertFalse(controllerEnabled);
        assertEq(cvc.getRawExecutionContext(), 1 << 184);
    }

    function invariant_AccountAndVaultStatusChecks() external {
        (
            uint8 accountStatusChecksNumElements,
            address[] memory accountStatusChecks,
            uint8 vaultStatusChecksNumElements,
            address[] memory vaultStatusChecks
        ) = cvc.exposeAccountAndVaultStatusCheck();

        assertTrue(accountStatusChecksNumElements == 0);
        for (uint i = 0; i < accountStatusChecks.length; i++) {
            assertTrue(accountStatusChecks[i] == address(0));
        }

        assertTrue(vaultStatusChecksNumElements == 0);
        for (uint i = 0; i < vaultStatusChecks.length; i++) {
            assertTrue(vaultStatusChecks[i] == address(0));
        }
    }

    function invariant_controllers_collaterals() external {
        address[] memory touchedAccounts = cvc.getTouchedAccounts();
        for (uint i = 0; i < touchedAccounts.length; i++) {
            // controllers
            (
                uint8 accountControllersNumElements,
                address[] memory accountControllersArray
            ) = cvc.exposeAccountControllers(touchedAccounts[i]);

            assertTrue(
                accountControllersNumElements == 0 ||
                    accountControllersNumElements == 1
            );
            assertTrue(
                (accountControllersNumElements == 0 &&
                    accountControllersArray[0] == address(0)) ||
                    (accountControllersNumElements == 1 &&
                        accountControllersArray[0] != address(0))
            );

            for (uint j = 1; j < accountControllersArray.length; j++) {
                assertTrue(accountControllersArray[j] == address(0));
            }

            // collaterals
            (
                uint8 accountCollateralsNumCollaterals,
                address[] memory accountCollateralsArray
            ) = cvc.exposeAccountCollaterals(touchedAccounts[i]);

            assertTrue(accountCollateralsNumCollaterals <= Set.MAX_ELEMENTS);
            for (uint j = 0; j < accountCollateralsNumCollaterals; j++) {
                assertTrue(accountCollateralsArray[j] != address(0));
            }

            // verify that none entry is duplicated
            for (uint j = 1; j < accountCollateralsNumCollaterals; j++) {
                for (uint k = 0; k < j; k++) {
                    assertTrue(
                        accountCollateralsArray[j] != accountCollateralsArray[k]
                    );
                }
            }
        }
    }
}
