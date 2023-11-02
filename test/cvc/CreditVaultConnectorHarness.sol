// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "./CreditVaultConnectorScribble.sol";
import "../utils/mocks/Vault.sol";

// helper contract that allows to set CVC's internal state and overrides original
// CVC functions in order to verify the account and vault checks
contract CreditVaultConnectorHarness is CreditVaultConnectorScribble {
    using ExecutionContext for EC;
    using Set for SetStorage;

    address[] internal expectedAccountsChecked;
    address[] internal expectedVaultsChecked;

    function isFuzzSender() internal view returns (bool) {
        // as per https://fuzzing-docs.diligence.tools/getting-started-1/seed-state
        // fuzzer always sends transactions from the EOA while Foundry does it from the test contract
        if (msg.sender.code.length == 0) return true;
        else return false;
    }

    function reset() external {
        delete accountStatusChecks;
        delete vaultStatusChecks;
        delete expectedAccountsChecked;
        delete expectedVaultsChecked;
    }

    function clearExpectedChecks() public {
        delete expectedAccountsChecked;
        delete expectedVaultsChecked;
    }

    function pushExpectedAccountsCheck(address account) external {
        expectedAccountsChecked.push(account);
    }

    function pushExpectedVaultsCheck(address vault) external {
        expectedVaultsChecked.push(vault);
    }

    function getExpectedAccountStatusChecks()
        external
        view
        returns (address[] memory)
    {
        return expectedAccountsChecked;
    }

    function getExpectedVaultStatusChecks()
        external
        view
        returns (address[] memory)
    {
        return expectedVaultsChecked;
    }

    function setCallDepth(uint8 depth) external {
        if (isFuzzSender()) return;
        executionContext = EC.wrap(
            (EC.unwrap(executionContext) & ~uint(0xff)) | depth
        );
    }

    function setChecksLock(bool locked) external {
        if (isFuzzSender()) return;

        if (locked) {
            executionContext = executionContext.setChecksInProgress();
        } else {
            executionContext = EC.wrap(
                EC.unwrap(executionContext) &
                    ~uint(0xFF000000000000000000000000000000000000000000)
            );
        }
    }

    function setImpersonateLock(bool locked) external {
        if (isFuzzSender()) return;

        if (locked) {
            executionContext = executionContext.setImpersonationInProgress();
        } else {
            executionContext = EC.wrap(
                EC.unwrap(executionContext) &
                    ~uint(0xFF00000000000000000000000000000000000000000000)
            );
        }
    }

    function setOperatorAuthenticated(bool authenticated) external {
        if (isFuzzSender()) return;

        if (authenticated) {
            executionContext = executionContext.setOperatorAuthenticated();
        } else {
            executionContext = executionContext.clearOperatorAuthenticated();
        }
    }

    function setSimulation(bool inProgress) external {
        if (isFuzzSender()) return;

        if (inProgress) {
            executionContext = executionContext.setSimulationInProgress();
        } else {
            executionContext = EC.wrap(
                EC.unwrap(executionContext) &
                    ~uint(0xFF000000000000000000000000000000000000000000000000)
            );
        }
    }

    function setOnBehalfOfAccount(address account) external {
        if (isFuzzSender()) return;
        executionContext = executionContext.setOnBehalfOfAccount(account);
    }

    // function overrides in order to verify the account and vault checks
    function requireAccountStatusCheck(
        address account
    ) public payable override {
        super.requireAccountStatusCheck(account);
        expectedAccountsChecked.push(account);
    }

    function requireAccountStatusCheckNow(
        address account
    ) public payable override {
        super.requireAccountStatusCheckNow(account);
        expectedAccountsChecked.push(account);
    }

    function requireAllAccountsStatusCheckNow() public payable override {
        address[] memory accounts = accountStatusChecks.get();

        super.requireAllAccountsStatusCheckNow();

        for (uint i = 0; i < accounts.length; ++i) {
            expectedAccountsChecked.push(accounts[i]);
        }
    }

    function requireVaultStatusCheck() public payable override {
        super.requireVaultStatusCheck();

        expectedVaultsChecked.push(msg.sender);
    }

    function requireVaultStatusCheckNow(address vault) public payable override {
        if (vaultStatusChecks.contains(vault)) {
            expectedVaultsChecked.push(vault);
        }

        super.requireVaultStatusCheckNow(vault);
    }

    function requireAccountAndVaultStatusCheck(
        address account
    ) public payable override {
        super.requireAccountAndVaultStatusCheck(account);

        expectedAccountsChecked.push(account);
        expectedVaultsChecked.push(msg.sender);
    }

    function requireAccountStatusCheckInternal(
        address account
    ) internal override {
        super.requireAccountStatusCheckInternal(account);

        address[] memory controllers = accountControllers[account].get();
        if (controllers.length == 1)
            Vault(controllers[0]).pushAccountStatusChecked(account);
    }

    function requireVaultStatusCheckInternal(address vault) internal override {
        super.requireVaultStatusCheckInternal(vault);

        Vault(vault).pushVaultStatusChecked();
    }

    function verifyVaultStatusChecks() public view {
        for (uint i = 0; i < expectedVaultsChecked.length; ++i) {
            require(
                Vault(expectedVaultsChecked[i])
                    .getVaultStatusChecked()
                    .length == 1,
                "verifyVaultStatusChecks"
            );
        }
    }

    function verifyAccountStatusChecks() public view {
        for (uint i = 0; i < expectedAccountsChecked.length; ++i) {
            address[] memory controllers = accountControllers[
                expectedAccountsChecked[i]
            ].get();

            require(
                controllers.length <= 1,
                "verifyAccountStatusChecks/length"
            );

            if (controllers.length == 0) continue;

            address[] memory accounts = Vault(controllers[0])
                .getAccountStatusChecked();

            uint counter = 0;
            for (uint j = 0; j < accounts.length; ++j) {
                if (accounts[j] == expectedAccountsChecked[i]) counter++;
            }

            require(counter == 1, "verifyAccountStatusChecks/counter");
        }
    }
}
