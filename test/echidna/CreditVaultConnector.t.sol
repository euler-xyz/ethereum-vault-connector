// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "../../src/interfaces/ICreditVault.sol";
import "../../src/interfaces/ICreditVaultConnector.sol";
import "../../src/interfaces/IERC1271.sol";
import "../cvc/CreditVaultConnectorEchidna.sol";

interface IHevm {
    function prank(address) external;
}

contract SignerEchidna {
    function isValidSignature(
        bytes32,
        bytes memory
    ) external pure returns (bytes4 magicValue) {
        return IERC1271.isValidSignature.selector;
    }
}

contract TargetEchidna {
    fallback() external payable {}
}

contract VaultEchidna is ICreditVault {
    IHevm internal constant hevm =
        IHevm(address(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D));
    CreditVaultConnectorEchidna internal constant cvc =
        CreditVaultConnectorEchidna(payable(address(0xdead)));
    TargetEchidna internal immutable targetEchidna =
        TargetEchidna(payable(address(0xbeefbeef)));

    function disableController(address account) external {
        cvc.disableController(account);
    }

    function checkAccountStatus(
        address account,
        address[] calldata
    ) public returns (bytes4) {
        // try to reenter the CVC

        uint152 prefix = uint152(uint160(account) >> 8);
        uint nextNonce = cvc.getNonce(prefix, 0) + 1;
        hevm.prank(account);
        try cvc.setNonce(prefix, 0, nextNonce) {} catch {}

        hevm.prank(account);
        try cvc.setOperator(prefix, address(this), 0) {} catch {}

        hevm.prank(account);
        try cvc.setAccountOperator(account, address(this), false) {} catch {}

        hevm.prank(account);
        try cvc.disableCollateral(account, address(this)) {} catch {}

        hevm.prank(account);
        try cvc.enableCollateral(account, address(this)) {} catch {}

        hevm.prank(account);
        try cvc.enableController(account, address(this)) {} catch {}

        hevm.prank(address(this));
        try cvc.disableController(account) {} catch {}

        hevm.prank(account);
        try cvc.call(address(this), account, "") {} catch {}

        hevm.prank(address(this));
        try cvc.impersonate(address(this), account, "") {} catch {}

        ICVC.BatchItem[] memory items = new ICVC.BatchItem[](1);
        items[0].targetContract = address(this);
        items[0].onBehalfOfAccount = account;
        items[0].value = 0;
        items[0].data = "";
        hevm.prank(account);
        try cvc.batch(items) {} catch {}

        try cvc.checkAccountStatus(account) {} catch {}
        try cvc.requireAccountStatusCheck(account) {} catch {}
        try cvc.requireAccountStatusCheckNow(account) {} catch {}
        try cvc.requireAllAccountsStatusCheckNow() {} catch {}

        hevm.prank(address(this));
        try cvc.forgiveAccountStatusCheck(account) {} catch {}

        hevm.prank(address(this));
        try cvc.requireVaultStatusCheck() {} catch {}

        try cvc.requireVaultStatusCheckNow(address(this)) {} catch {}
        try cvc.requireAllVaultsStatusCheckNow() {} catch {}

        hevm.prank(address(this));
        try cvc.forgiveVaultStatusCheck() {} catch {}

        hevm.prank(address(this));
        try cvc.requireAccountAndVaultStatusCheck(account) {} catch {}

        return this.checkAccountStatus.selector;
    }

    function checkVaultStatus() public returns (bytes4) {
        // try to reenter the CVC
        address account = address(1);

        uint152 prefix = uint152(uint160(account) >> 8);
        uint nextNonce = cvc.getNonce(prefix, 0) + 1;
        hevm.prank(account);
        try cvc.setNonce(prefix, 0, nextNonce) {} catch {}

        hevm.prank(account);
        try cvc.setOperator(prefix, address(this), 0) {} catch {}

        hevm.prank(account);
        try cvc.setAccountOperator(account, address(this), false) {} catch {}

        hevm.prank(account);
        try cvc.disableCollateral(account, address(this)) {} catch {}

        hevm.prank(account);
        try cvc.enableCollateral(account, address(this)) {} catch {}

        hevm.prank(account);
        try cvc.enableController(account, address(this)) {} catch {}

        hevm.prank(address(this));
        try cvc.disableController(account) {} catch {}

        hevm.prank(account);
        try cvc.call(address(this), account, "") {} catch {}

        hevm.prank(address(this));
        cvc.enableCollateral(account, address(this));
        try cvc.impersonate(address(this), account, "") {} catch {}

        ICVC.BatchItem[] memory items = new ICVC.BatchItem[](1);
        items[0].targetContract = address(this);
        items[0].onBehalfOfAccount = account;
        items[0].value = 0;
        items[0].data = "";
        hevm.prank(account);
        try cvc.batch(items) {} catch {}

        try cvc.checkAccountStatus(account) {} catch {}
        try cvc.requireAccountStatusCheck(account) {} catch {}
        try cvc.requireAccountStatusCheckNow(account) {} catch {}
        try cvc.requireAllAccountsStatusCheckNow() {} catch {}

        hevm.prank(address(this));
        try cvc.forgiveAccountStatusCheck(account) {} catch {}

        hevm.prank(address(this));
        try cvc.requireVaultStatusCheck() {} catch {}

        try cvc.requireVaultStatusCheckNow(address(this)) {} catch {}
        try cvc.requireAllVaultsStatusCheckNow() {} catch {}

        hevm.prank(address(this));
        try cvc.forgiveVaultStatusCheck() {} catch {}

        hevm.prank(address(this));
        try cvc.requireAccountAndVaultStatusCheck(account) {} catch {}

        return this.checkVaultStatus.selector;
    }

    fallback() external payable {
        cvc.requireVaultStatusCheck();

        // try to reenter the CVC
        address account = address(2);

        uint152 prefix = uint152(uint160(account) >> 8);
        uint nextNonce = cvc.getNonce(prefix, 0) + 1;
        hevm.prank(account);
        try cvc.setNonce(prefix, 0, nextNonce) {} catch {}

        hevm.prank(account);
        try cvc.setOperator(prefix, address(this), 0) {} catch {}

        hevm.prank(account);
        try cvc.setAccountOperator(account, address(this), false) {} catch {}

        hevm.prank(account);
        try cvc.disableCollateral(account, address(this)) {} catch {}

        hevm.prank(account);
        try cvc.enableCollateral(account, address(this)) {} catch {}

        hevm.prank(account);
        try cvc.enableController(account, address(this)) {} catch {}

        hevm.prank(address(this));
        try cvc.disableController(account) {} catch {}

        hevm.prank(account);
        try cvc.call(address(targetEchidna), account, "") {} catch {}

        hevm.prank(account);
        try cvc.enableCollateral(account, address(targetEchidna)) {} catch {}

        hevm.prank(address(this));
        try cvc.impersonate(address(targetEchidna), account, "") {} catch {}

        ICVC.BatchItem[] memory items = new ICVC.BatchItem[](1);
        items[0].targetContract = address(targetEchidna);
        items[0].onBehalfOfAccount = account;
        items[0].value = 0;
        items[0].data = "";
        hevm.prank(account);
        try cvc.batch(items) {} catch {}

        try cvc.checkAccountStatus(account) {} catch {}
        try cvc.requireAccountStatusCheck(account) {} catch {}
        try cvc.requireAccountStatusCheckNow(account) {} catch {}
        try cvc.requireAllAccountsStatusCheckNow() {} catch {}

        hevm.prank(address(this));
        try cvc.forgiveAccountStatusCheck(account) {} catch {}

        hevm.prank(address(this));
        try cvc.requireVaultStatusCheck() {} catch {}

        try cvc.requireVaultStatusCheckNow(address(this)) {} catch {}
        try cvc.requireAllVaultsStatusCheckNow() {} catch {}

        hevm.prank(address(this));
        try cvc.forgiveVaultStatusCheck() {} catch {}

        hevm.prank(address(this));
        try cvc.requireAccountAndVaultStatusCheck(account) {} catch {}
    }

    receive() external payable {}
}

contract EchidnaTest {
    IHevm internal constant hevm =
        IHevm(address(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D));
    CreditVaultConnectorEchidna internal immutable cvc =
        CreditVaultConnectorEchidna(payable(address(0xdead)));
    VaultEchidna internal immutable vaultEchidna =
        VaultEchidna(payable(address(0xbeef)));
    SignerEchidna internal immutable signerEchidna =
        SignerEchidna(address(0xbeefbeefbeef));

    function enableCollateral(address account, address vault) public payable {
        if (account == address(cvc)) return;
        hevm.prank(account);
        cvc.enableCollateral(account, vault);
    }

    function disableCollateral(address account, address vault) public payable {
        if (account == address(cvc)) return;
        hevm.prank(account);
        cvc.disableCollateral(account, vault);
    }

    function enableController(address account, address) public payable {
        if (account == address(cvc)) return;
        hevm.prank(account);
        cvc.enableController(account, address(vaultEchidna));
    }

    function disableController(address account) public payable {
        if (account == address(cvc)) return;
        if (cvc.getControllers(account).length > 0) {
            hevm.prank(cvc.getControllers(account)[0]);
        }
        cvc.disableController(account);
    }

    function call(
        address onBehalfOfAccount,
        bytes calldata data
    ) public payable {
        if (onBehalfOfAccount == address(cvc)) return;
        hevm.prank(onBehalfOfAccount);
        cvc.call(address(vaultEchidna), onBehalfOfAccount, data);
    }

    function impersonate(
        address onBehalfOfAccount,
        bytes calldata data
    ) public payable {
        if (onBehalfOfAccount == address(cvc)) return;
        hevm.prank(onBehalfOfAccount);
        cvc.enableCollateral(onBehalfOfAccount, address(vaultEchidna));

        hevm.prank(onBehalfOfAccount);
        cvc.enableController(onBehalfOfAccount, address(vaultEchidna));

        hevm.prank(address(vaultEchidna));
        cvc.impersonate(address(vaultEchidna), onBehalfOfAccount, data);
    }

    function permit(
        bytes calldata data,
        bytes calldata signature
    ) public payable {
        cvc.permit(
            address(signerEchidna),
            0,
            cvc.getNonce(cvc.getAddressPrefix(address(cvc)), 0) + 1,
            block.timestamp,
            data,
            signature
        );
    }

    function batch(ICVC.BatchItem[] calldata items) public payable {
        if (items.length > 0) {
            ICVC.BatchItem[] memory _items = new ICVC.BatchItem[](1);

            if (items[0].onBehalfOfAccount == address(cvc)) return;

            _items[0].targetContract = address(vaultEchidna);
            _items[0].onBehalfOfAccount = items[0].onBehalfOfAccount;
            _items[0].value = 0;
            _items[0].data = items[0].data;

            hevm.prank(_items[0].onBehalfOfAccount);
            cvc.batch(_items);

            try cvc.batch(items) {} catch {}
        } else {
            cvc.batch(items);
        }
    }

    function checkAccountStatus(address account) public payable {
        cvc.checkAccountStatus(account);
    }

    function checkAccountStatus(address[] calldata accounts) public payable {
        cvc.checkAccountsStatus(accounts);
    }

    function requireAccountStatusCheck(address account) public payable {
        cvc.requireAccountStatusCheck(account);
    }

    function requireAccountsStatusCheck(
        address[] calldata accounts
    ) public payable {
        cvc.requireAccountsStatusCheck(accounts);
    }

    function requireAccountStatusCheckNow(address account) public payable {
        cvc.requireAccountStatusCheckNow(account);
    }

    function requireAccountsStatusCheckNow(
        address[] memory accounts
    ) public payable {
        cvc.requireAccountsStatusCheckNow(accounts);
    }

    function requireAllAccountsStatusCheckNow() public payable {
        cvc.requireAllAccountsStatusCheckNow();
    }

    function forgiveAccountStatusCheck(address account) public payable {
        cvc.forgiveAccountStatusCheck(account);
    }

    function forgiveAccountsStatusCheck(
        address[] memory account
    ) public payable {
        cvc.forgiveAccountsStatusCheck(account);
    }

    function requireVaultStatusCheck() public payable {
        cvc.requireVaultStatusCheck();
    }

    function requireVaultStatusCheckNow(address vault) public payable {
        cvc.requireVaultStatusCheckNow(vault);
    }

    function requireVaultsStatusCheckNow(
        address[] calldata vaults
    ) public payable {
        cvc.requireVaultsStatusCheckNow(vaults);
    }

    function requireAllVaultsStatusCheckNow() public payable {
        cvc.requireAllVaultsStatusCheckNow();
    }

    function forgiveVaultStatusCheck() public payable {
        cvc.forgiveVaultStatusCheck();
    }

    function requireAccountAndVaultStatusCheck(address account) public payable {
        cvc.requireAccountAndVaultStatusCheck(account);
    }
}
