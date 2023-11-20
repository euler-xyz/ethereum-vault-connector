// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "../../src/interfaces/IVault.sol";
import "../../src/interfaces/IEthereumVaultConnector.sol";
import "../../src/interfaces/IERC1271.sol";
import "../evc/EthereumVaultConnectorEchidna.sol";

interface IHevm {
    function prank(address) external;
}

contract SignerEchidna {
    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4 magicValue) {
        return IERC1271.isValidSignature.selector;
    }
}

contract TargetEchidna {
    fallback() external payable {}
}

contract VaultEchidna is IVault {
    IHevm internal constant hevm = IHevm(address(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D));
    EthereumVaultConnectorEchidna internal constant evc = EthereumVaultConnectorEchidna(payable(address(0xdead)));
    TargetEchidna internal immutable targetEchidna = TargetEchidna(payable(address(0xbeefbeef)));

    function disableController(address account) external {
        evc.disableController(account);
    }

    function checkAccountStatus(address account, address[] calldata) public returns (bytes4) {
        // try to reenter the EVC

        uint152 prefix = uint152(uint160(account) >> 8);
        uint256 nextNonce = evc.getNonce(prefix, 0);
        hevm.prank(account);
        try evc.setNonce(prefix, 0, evc.getNonce(prefix, 0)) {} catch {}

        hevm.prank(account);
        try evc.setOperator(prefix, address(this), 0) {} catch {}

        hevm.prank(account);
        try evc.setAccountOperator(account, address(this), false) {} catch {}

        hevm.prank(account);
        try evc.disableCollateral(account, address(this)) {} catch {}

        hevm.prank(account);
        try evc.enableCollateral(account, address(this)) {} catch {}

        hevm.prank(account);
        try evc.enableController(account, address(this)) {} catch {}

        hevm.prank(address(this));
        try evc.disableController(account) {} catch {}

        hevm.prank(account);
        try evc.recoverRemainingETH(account) {} catch {}

        try evc.callback(account, 0, "") {} catch {}

        hevm.prank(account);
        try evc.call(address(this), account, 0, "") {} catch {}

        hevm.prank(address(this));
        try evc.impersonate(address(this), account, 0, "") {} catch {}

        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(this);
        items[0].onBehalfOfAccount = account;
        items[0].value = 0;
        items[0].data = "";
        hevm.prank(account);
        try evc.batch(items) {} catch {}

        try evc.requireAccountStatusCheck(account) {} catch {}
        try evc.requireAccountStatusCheckNow(account) {} catch {}
        try evc.requireAllAccountsStatusCheckNow() {} catch {}

        hevm.prank(address(this));
        try evc.forgiveAccountStatusCheck(account) {} catch {}

        hevm.prank(address(this));
        try evc.requireVaultStatusCheck() {} catch {}

        hevm.prank(address(this));
        try evc.requireVaultStatusCheckNow() {} catch {}

        try evc.requireAllVaultsStatusCheckNow() {} catch {}

        hevm.prank(address(this));
        try evc.forgiveVaultStatusCheck() {} catch {}

        hevm.prank(address(this));
        try evc.requireAccountAndVaultStatusCheck(account) {} catch {}

        return this.checkAccountStatus.selector;
    }

    function checkVaultStatus() public returns (bytes4) {
        // try to reenter the EVC
        address account = address(1);

        uint152 prefix = uint152(uint160(account) >> 8);
        uint256 nextNonce = evc.getNonce(prefix, 0);
        hevm.prank(account);
        try evc.setNonce(prefix, 0, nextNonce) {} catch {}

        hevm.prank(account);
        try evc.setOperator(prefix, address(this), 0) {} catch {}

        hevm.prank(account);
        try evc.setAccountOperator(account, address(this), false) {} catch {}

        hevm.prank(account);
        try evc.disableCollateral(account, address(this)) {} catch {}

        hevm.prank(account);
        try evc.enableCollateral(account, address(this)) {} catch {}

        hevm.prank(account);
        try evc.enableController(account, address(this)) {} catch {}

        hevm.prank(address(this));
        try evc.disableController(account) {} catch {}

        hevm.prank(account);
        try evc.recoverRemainingETH(account) {} catch {}

        try evc.callback(account, 0, "") {} catch {}

        hevm.prank(account);
        try evc.call(address(this), account, 0, "") {} catch {}

        hevm.prank(address(this));
        evc.enableCollateral(account, address(this));
        try evc.impersonate(address(this), account, 0, "") {} catch {}

        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(this);
        items[0].onBehalfOfAccount = account;
        items[0].value = 0;
        items[0].data = "";
        hevm.prank(account);
        try evc.batch(items) {} catch {}

        try evc.requireAccountStatusCheck(account) {} catch {}
        try evc.requireAccountStatusCheckNow(account) {} catch {}
        try evc.requireAllAccountsStatusCheckNow() {} catch {}

        hevm.prank(address(this));
        try evc.forgiveAccountStatusCheck(account) {} catch {}

        hevm.prank(address(this));
        try evc.requireVaultStatusCheck() {} catch {}

        hevm.prank(address(this));
        try evc.requireVaultStatusCheckNow() {} catch {}

        try evc.requireAllVaultsStatusCheckNow() {} catch {}

        hevm.prank(address(this));
        try evc.forgiveVaultStatusCheck() {} catch {}

        hevm.prank(address(this));
        try evc.requireAccountAndVaultStatusCheck(account) {} catch {}

        return this.checkVaultStatus.selector;
    }

    fallback() external payable {
        evc.requireVaultStatusCheck();

        // try to reenter the EVC
        address account = address(2);

        uint152 prefix = uint152(uint160(account) >> 8);
        uint256 nextNonce = evc.getNonce(prefix, 0);
        hevm.prank(account);
        try evc.setNonce(prefix, 0, nextNonce) {} catch {}

        hevm.prank(account);
        try evc.setOperator(prefix, address(this), 0) {} catch {}

        hevm.prank(account);
        try evc.setAccountOperator(account, address(this), false) {} catch {}

        hevm.prank(account);
        try evc.disableCollateral(account, address(this)) {} catch {}

        hevm.prank(account);
        try evc.enableCollateral(account, address(this)) {} catch {}

        hevm.prank(account);
        try evc.enableController(account, address(this)) {} catch {}

        hevm.prank(address(this));
        try evc.disableController(account) {} catch {}

        hevm.prank(account);
        try evc.recoverRemainingETH(account) {} catch {}

        hevm.prank(account);
        try evc.call(address(targetEchidna), account, 0, "") {} catch {}

        hevm.prank(account);
        try evc.enableCollateral(account, address(targetEchidna)) {} catch {}

        hevm.prank(address(this));
        try evc.impersonate(address(targetEchidna), account, 0, "") {} catch {}

        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0].targetContract = address(targetEchidna);
        items[0].onBehalfOfAccount = account;
        items[0].value = 0;
        items[0].data = "";
        hevm.prank(account);
        try evc.batch(items) {} catch {}

        try evc.requireAccountStatusCheck(account) {} catch {}
        try evc.requireAccountStatusCheckNow(account) {} catch {}
        try evc.requireAllAccountsStatusCheckNow() {} catch {}

        hevm.prank(address(this));
        try evc.forgiveAccountStatusCheck(account) {} catch {}

        hevm.prank(address(this));
        try evc.requireVaultStatusCheck() {} catch {}

        hevm.prank(address(this));
        try evc.requireVaultStatusCheckNow() {} catch {}

        try evc.requireAllVaultsStatusCheckNow() {} catch {}

        hevm.prank(address(this));
        try evc.forgiveVaultStatusCheck() {} catch {}

        hevm.prank(address(this));
        try evc.requireAccountAndVaultStatusCheck(account) {} catch {}
    }

    receive() external payable {}
}

contract EchidnaTest {
    IHevm internal constant hevm = IHevm(address(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D));
    EthereumVaultConnectorEchidna internal immutable evc = EthereumVaultConnectorEchidna(payable(address(0xdead)));
    VaultEchidna internal immutable vaultEchidna = VaultEchidna(payable(address(0xbeef)));
    SignerEchidna internal immutable signerEchidna = SignerEchidna(address(0xbeefbeefbeef));

    function enableCollateral(address account, address vault) public payable {
        if (account == address(0) || account == address(evc)) return;
        hevm.prank(account);
        evc.enableCollateral(account, vault);
    }

    function disableCollateral(address account, address vault) public payable {
        if (account == address(0) || account == address(evc)) return;
        hevm.prank(account);
        evc.disableCollateral(account, vault);
    }

    function enableController(address account, address) public payable {
        if (account == address(0) || account == address(evc)) return;
        hevm.prank(account);
        evc.enableController(account, address(vaultEchidna));
    }

    function disableController(address account) public payable {
        if (account == address(0) || account == address(evc)) return;
        if (evc.getControllers(account).length > 0) {
            hevm.prank(evc.getControllers(account)[0]);
        }
        evc.disableController(account);
    }

    function permit(bytes calldata data, bytes calldata signature) public payable {
        evc.permit(
            address(signerEchidna),
            0,
            evc.getNonce(evc.getAddressPrefix(address(evc)), 0),
            block.timestamp,
            0,
            data,
            signature
        );
    }

    function recoverRemainingETH(address recipient) public payable {
        if (recipient == address(evc)) return;
        hevm.prank(address(recipient));
        evc.recoverRemainingETH(recipient);
    }

    function callback(address onBehalfOfAccount, bytes calldata data) public payable {
        if (onBehalfOfAccount == address(0) || onBehalfOfAccount == address(evc)) return;
        hevm.prank(address(vaultEchidna));
        evc.callback(onBehalfOfAccount, 0, data);
    }

    function call(address onBehalfOfAccount, bytes calldata data) public payable {
        if (onBehalfOfAccount == address(0) || onBehalfOfAccount == address(evc)) return;
        hevm.prank(onBehalfOfAccount);
        evc.call(address(vaultEchidna), onBehalfOfAccount, 0, data);
    }

    function impersonate(address onBehalfOfAccount, bytes calldata data) public payable {
        if (onBehalfOfAccount == address(0) || onBehalfOfAccount == address(evc)) return;

        hevm.prank(onBehalfOfAccount);
        evc.enableCollateral(onBehalfOfAccount, address(vaultEchidna));

        hevm.prank(onBehalfOfAccount);
        evc.enableController(onBehalfOfAccount, address(vaultEchidna));

        hevm.prank(address(vaultEchidna));
        evc.impersonate(address(vaultEchidna), onBehalfOfAccount, 0, data);
    }

    function batch(IEVC.BatchItem[] calldata items) public payable {
        if (items.length > 0) {
            IEVC.BatchItem[] memory _items = new IEVC.BatchItem[](1);

            for (uint256 i; i < items.length; ++i) {
                if (items[i].onBehalfOfAccount == address(0) || items[i].onBehalfOfAccount == address(evc)) return;
            }

            _items[0].targetContract = address(vaultEchidna);
            _items[0].onBehalfOfAccount = items[0].onBehalfOfAccount;
            _items[0].value = 0;
            _items[0].data = items[0].data;

            hevm.prank(_items[0].onBehalfOfAccount);
            evc.batch(_items);

            try evc.batch(items) {} catch {}
        } else {
            evc.batch(items);
        }
    }

    function requireAccountStatusCheck(address account) public payable {
        evc.requireAccountStatusCheck(account);
    }

    function requireAccountStatusCheckNow(address account) public payable {
        evc.requireAccountStatusCheckNow(account);
    }

    function requireAllAccountsStatusCheckNow() public payable {
        evc.requireAllAccountsStatusCheckNow();
    }

    function forgiveAccountStatusCheck(address account) public payable {
        evc.forgiveAccountStatusCheck(account);
    }

    function requireVaultStatusCheck() public payable {
        evc.requireVaultStatusCheck();
    }

    function requireVaultStatusCheckNow() public payable {
        evc.requireVaultStatusCheckNow();
    }

    function requireAllVaultsStatusCheckNow() public payable {
        evc.requireAllVaultsStatusCheckNow();
    }

    function forgiveVaultStatusCheck() public payable {
        evc.forgiveVaultStatusCheck();
    }

    function requireAccountAndVaultStatusCheck(address account) public payable {
        evc.requireAccountAndVaultStatusCheck(account);
    }
}
