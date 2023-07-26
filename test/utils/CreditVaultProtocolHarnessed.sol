// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "src/CreditVaultProtocol.sol";
import "./mocks/Vault.sol";

// helper contract that allows to set CVP's internal state and overrides original
// CVP functions in order to verify the account and vault checks
contract CreditVaultProtocolHarnessed is CreditVaultProtocol {
    using Set for SetStorage;

    address[] internal expectedAccountsChecked;
    address[] internal expectedVaultsChecked;

    function reset() external {
        delete accountStatusChecks;
        delete vaultStatusChecks;
        delete accountStatusCheckIgnoredFrom;
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

    function setBatchDepth(uint8 depth) external {
        executionContext.batchDepth = depth;
    }

    function setChecksInProgressLock(bool locked) external {
        executionContext.checksInProgressLock = locked;
    }

    function setOnBehalfOfAccount(address account) external {
        executionContext.onBehalfOfAccount = account;
    }

    function setControllerToCollateralCallLock(bool locked) external {
        executionContext.controllerToCollateralCallLock = locked;
    }

    function setAccountStatusCheckIgnoredFrom(address from) external {
        accountStatusCheckIgnoredFrom = from;
    }

    function getAccountStatusCheckIgnoredFrom()
        external
        view
        returns (address)
    {
        return accountStatusCheckIgnoredFrom;
    }

    // function overrides in order to verify the account and vault checks
    function requireAccountStatusCheck(address account) public override {
        address accountStatusCheckIgnoredFromCache = accountStatusCheckIgnoredFrom;

        super.requireAccountStatusCheck(account);

        if (
            !executionContext.controllerToCollateralCallLock ||
            executionContext.onBehalfOfAccount != account ||
            accountStatusCheckIgnoredFromCache != msg.sender
        ) expectedAccountsChecked.push(account);
    }

    function requireAccountsStatusCheck(
        address[] calldata accounts
    ) public override {
        address accountStatusCheckIgnoredFromCache = accountStatusCheckIgnoredFrom;

        super.requireAccountsStatusCheck(accounts);

        for (uint i = 0; i < accounts.length; ++i) {
            if (
                !executionContext.controllerToCollateralCallLock ||
                executionContext.onBehalfOfAccount != accounts[i] ||
                accountStatusCheckIgnoredFromCache != msg.sender
            ) expectedAccountsChecked.push(accounts[i]);
        }
    }

    function requireAccountStatusCheckNow(address account) public override {
        super.requireAccountStatusCheckNow(account);

        expectedAccountsChecked.push(account);
    }

    function requireAccountsStatusCheckNow(
        address[] calldata accounts
    ) public override {
        super.requireAccountsStatusCheckNow(accounts);

        for (uint i = 0; i < accounts.length; ++i) {
            expectedAccountsChecked.push(accounts[i]);
        }
    }

    function requireVaultStatusCheck() public override {
        super.requireVaultStatusCheck();

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

    function verifyStorage() public view {
        require(
            executionContext.batchDepth == BATCH_DEPTH__INIT,
            "verifyStorage/checks-deferred"
        );
        require(
            executionContext.checksInProgressLock == false,
            "verifyStorage/checks-in-progress-lock"
        );
        require(
            executionContext.controllerToCollateralCallLock == false,
            "verifyStorage/controller-to-collateral-call-lock"
        );
        require(
            executionContext.onBehalfOfAccount == address(0),
            "verifyStorage/on-behalf-of-account"
        );

        require(
            accountStatusChecks.numElements == 0,
            "verifyStorage/account-status-checks/numElements"
        );
        require(
            accountStatusChecks.firstElement == address(0),
            "verifyStorage/account-status-checks/firstElement"
        );

        for (uint i = 0; i < Set.MAX_ELEMENTS; ++i) {
            require(
                accountStatusChecks.elements[i] == address(0),
                "verifyStorage/account-status-checks/elements"
            );
        }

        require(
            vaultStatusChecks.numElements == 0,
            "verifyStorage/vault-status-checks/numElements"
        );
        require(
            vaultStatusChecks.firstElement == address(0),
            "verifyStorage/vault-status-checks/firstElement"
        );

        for (uint i = 0; i < Set.MAX_ELEMENTS; ++i) {
            require(
                vaultStatusChecks.elements[i] == address(0),
                "verifyStorage/vault-status-checks/elements"
            );
        }

        require(
            accountStatusCheckIgnoredFrom == address(0),
            "verifyStorage/account-status-check-ignored-from"
        );

        // for coverage
        invariantsCheck();
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
