// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "./Target.sol";
import "../../../src/interfaces/ICreditVault.sol";

// mock vault contract that implements required interface and helps with status checks verification
contract Vault is ICreditVault, Target {
    ICVC public immutable cvc;

    uint internal vaultStatusState;
    uint internal accountStatusState;

    bool[] internal vaultStatusChecked;
    address[] internal accountStatusChecked;

    constructor(ICVC _cvc) {
        cvc = _cvc;
    }

    function reset() external {
        vaultStatusState = 0;
        accountStatusState = 0;
        delete vaultStatusChecked;
        delete accountStatusChecked;
    }

    function clearChecks() external {
        delete vaultStatusChecked;
        delete accountStatusChecked;
    }

    function setVaultStatusState(uint state) external {
        vaultStatusState = state;
    }

    function setAccountStatusState(uint state) external {
        accountStatusState = state;
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

    function getAccountStatusChecked()
        external
        view
        returns (address[] memory)
    {
        return accountStatusChecked;
    }

    function disableController(address account) external virtual override {
        cvc.disableController(account);
    }

    function checkVaultStatus()
        external
        virtual
        override
        returns (bytes4 magicValue)
    {
        try cvc.getCurrentOnBehalfOfAccount(address(0)) {
            revert("cvs/on-behalf-of-account");
        } catch (bytes memory reason) {
            if (
                bytes4(reason) !=
                Errors.CVC_OnBehalfOfAccountNotAuthenticated.selector
            ) {
                revert("cvs/on-behalf-of-account-2");
            }
        }
        require(cvc.areChecksInProgress(), "cvs/checks-not-in-progress");

        if (vaultStatusState == 0) {
            return 0x4b3d1223;
        } else if (vaultStatusState == 1) {
            revert("vault status violation");
        } else {
            return bytes4(uint32(1));
        }
    }

    function checkAccountStatus(
        address,
        address[] memory
    ) external virtual override returns (bytes4 magicValue) {
        try cvc.getCurrentOnBehalfOfAccount(address(0)) {
            revert("cas/on-behalf-of-account");
        } catch (bytes memory reason) {
            if (
                bytes4(reason) !=
                Errors.CVC_OnBehalfOfAccountNotAuthenticated.selector
            ) {
                revert("cas/on-behalf-of-account-2");
            }
        }
        require(cvc.areChecksInProgress(), "cas/checks-not-in-progress");

        if (accountStatusState == 0) {
            return 0xb168c58f;
        } else if (accountStatusState == 1) {
            revert("account status violation");
        } else {
            return bytes4(uint32(2));
        }
    }

    function requireChecks(address account) external payable {
        cvc.requireAccountStatusCheck(account);
        cvc.requireVaultStatusCheck();
    }

    function requireChecksWithSimulationCheck(
        address account,
        bool expectedSimulationInProgress
    ) external payable {
        require(
            cvc.isSimulationInProgress() == expectedSimulationInProgress,
            "requireChecksWithSimulationCheck/simulation"
        );

        cvc.requireAccountStatusCheck(account);
        cvc.requireVaultStatusCheck();
    }

    function call(address target, bytes memory data) external payable virtual {
        (bool success, ) = target.call{value: msg.value}(data);
        require(success, "call/failed");
    }
}

contract VaultMalicious is Vault {
    bytes4 internal expectedErrorSelector;

    constructor(ICVC _cvc) Vault(_cvc) {}

    function setExpectedErrorSelector(bytes4 selector) external {
        expectedErrorSelector = selector;
    }

    function callBatch() external payable {
        (bool success, bytes memory result) = address(cvc).call(
            abi.encodeWithSelector(cvc.batch.selector, new ICVC.BatchItem[](0))
        );

        require(!success, "callBatch/succeeded");
        if (bytes4(result) == expectedErrorSelector)
            revert("callBatch/expected-error");
    }

    function checkVaultStatus() external virtual override returns (bytes4) {
        try cvc.getCurrentOnBehalfOfAccount(address(0)) {
            revert("cvs/on-behalf-of-account");
        } catch (bytes memory reason) {
            if (
                bytes4(reason) !=
                Errors.CVC_OnBehalfOfAccountNotAuthenticated.selector
            ) {
                revert("cvs/on-behalf-of-account-2");
            }
        }
        require(cvc.areChecksInProgress(), "cvs/checks-not-in-progress");

        if (expectedErrorSelector == 0) {
            return this.checkVaultStatus.selector;
        }

        (bool success, bytes memory result) = address(cvc).call(
            abi.encodeWithSelector(cvc.batch.selector, new ICVC.BatchItem[](0))
        );

        if (success || bytes4(result) != expectedErrorSelector) {
            return this.checkVaultStatus.selector;
        }

        revert("malicious vault");
    }

    function checkAccountStatus(
        address,
        address[] memory
    ) external override returns (bytes4) {
        try cvc.getCurrentOnBehalfOfAccount(address(0)) {
            revert("cas/on-behalf-of-account");
        } catch (bytes memory reason) {
            if (
                bytes4(reason) !=
                Errors.CVC_OnBehalfOfAccountNotAuthenticated.selector
            ) {
                revert("cas/on-behalf-of-account-2");
            }
        }
        require(cvc.areChecksInProgress(), "cas/checks-not-in-progress");

        if (expectedErrorSelector == 0) {
            return this.checkAccountStatus.selector;
        }

        (bool success, bytes memory result) = address(cvc).call(
            abi.encodeWithSelector(cvc.batch.selector, new ICVC.BatchItem[](0))
        );

        if (success || bytes4(result) != expectedErrorSelector) {
            return this.checkAccountStatus.selector;
        }

        revert("malicious vault");
    }
}
