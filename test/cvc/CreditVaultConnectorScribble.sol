// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "../../src/CreditVaultConnector.sol";

/// #define ownerOrOperator(address caller, address account) bool = (ownerLookup[uint152(uint160(account) >> 8)] == caller || (ownerLookup[uint152(uint160(account) >> 8)] == address(0) && (uint160(caller) | 0xFF) == (uint160(account) | 0xFF))) || operatorLookup[account][caller] >= block.timestamp;
/// #if_succeeds "batch state doesn't change" old(executionContext.isInBatch()) == executionContext.isInBatch();
/// #if_succeeds "on behalf account state doesn't change" old(executionContext.getOnBehalfOfAccount()) == executionContext.getOnBehalfOfAccount();
/// #if_succeeds "checks in progress state doesn't change" old(executionContext.areChecksInProgress()) == executionContext.areChecksInProgress();
/// #if_succeeds "impersonation in progress state doesn't change" old(executionContext.isImpersonationInProgress()) == executionContext.isImpersonationInProgress();
/// #if_succeeds "account status checks set is empty 1" !old(executionContext.isInBatch()) ==> old(accountStatusChecks.numElements) == 0 && accountStatusChecks.numElements == 0;
/// #if_succeeds "account status checks set is empty 2" !old(executionContext.isInBatch()) ==> old(accountStatusChecks.firstElement) == address(0) && accountStatusChecks.firstElement == address(0);
/// #if_succeeds "account status checks set is empty 3" !old(executionContext.isInBatch()) ==> forall(uint i in 0...20) accountStatusChecks.elements[i].value == address(0);
/// #if_succeeds "vault status checks set is empty 1" !old(executionContext.isInBatch()) ==> old(vaultStatusChecks.numElements) == 0 && vaultStatusChecks.numElements == 0;
/// #if_succeeds "vault status checks set is empty 2" !old(executionContext.isInBatch()) ==> old(vaultStatusChecks.firstElement) == address(0) && vaultStatusChecks.firstElement == address(0);
/// #if_succeeds "vault status checks set is empty 3" !old(executionContext.isInBatch()) ==> forall(uint i in 0...20) vaultStatusChecks.elements[i].value == address(0);
/// #if_succeeds "each account has at most 1 controller" !old(executionContext.isInBatch()) ==> forall(uint i in ownerLookup) forall(uint j in 0...256) accountControllers[address(uint160((i << 8) ^ j))].numElements <= 1;
/// #invariant "account status checks set has at most 20 elements" accountStatusChecks.numElements <= 20;
/// #invariant "vault status checks set has at most 20 elements" vaultStatusChecks.numElements <= 20;
contract CreditVaultConnectorScribble is CreditVaultConnector {
    using ExecutionContext for EC;
    using Set for SetStorage;

    /// #if_succeeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    function getExecutionContext(
        address controllerToCheck
    )
        public
        view
        virtual
        override
        returns (address onBehalfOfAccount, bool controllerEnabled)
    {
        return super.getExecutionContext(controllerToCheck);
    }

    /// #if_succeeds "only the account owner can call this" (address(this) != msg.sender && ownerLookup[uint152(uint160(account) >> 8)] == msg.sender) || (address(this) == msg.sender && ownerLookup[uint152(uint160(account) >> 8)] == executionContext.getOnBehalfOfAccount());
    function setNonce(
        address account,
        uint nonceNamespace,
        uint nonce
    ) public payable virtual override {
        super.setNonce(account, nonceNamespace, nonce);
    }

    /// #if_succeeds "only the account owner or operator can call this" ownerOrOperator(address(this) == msg.sender ? old(executionContext.getOnBehalfOfAccount()) : msg.sender, account);
    function setAccountOperator(
        address account,
        address operator,
        uint expiryTimestamp
    ) public payable virtual override {
        super.setAccountOperator(account, operator, expiryTimestamp);
    }

    /// #if_succeeds "only the account owner or operator can call this" ownerOrOperator(address(this) == msg.sender ? old(executionContext.getOnBehalfOfAccount()) : msg.sender, account);
    /// #if_succeeds "is non-reentant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isImpersonationInProgress());
    /// #if_succeeds "the vault is present in the collateral set 1" old(accountCollaterals[account].numElements) < 20 ==> accountCollaterals[account].contains(vault);
    /// #if_succeeds "number of vaults is equal to the collateral array length 1" accountCollaterals[account].numElements == accountCollaterals[account].get().length;
    /// #if_succeeds "collateral cannot be CVC" vault != address(this);
    function enableCollateral(
        address account,
        address vault
    ) public payable virtual override {
        super.enableCollateral(account, vault);
    }

    /// #if_succeeds "only the account owner or operator can call this" ownerOrOperator(address(this) == msg.sender ? old(executionContext.getOnBehalfOfAccount()) : msg.sender, account);
    /// #if_succeeds "is non-reentant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isImpersonationInProgress());
    /// #if_succeeds "the vault is not present the collateral set 2" !accountCollaterals[account].contains(vault);
    /// #if_succeeds "number of vaults is equal to the collateral array length 2" accountCollaterals[account].numElements == accountCollaterals[account].get().length;
    function disableCollateral(
        address account,
        address vault
    ) public payable virtual override {
        super.disableCollateral(account, vault);
    }

    /// #if_succeeds "only the account owner or operator can call this" ownerOrOperator(address(this) == msg.sender ? old(executionContext.getOnBehalfOfAccount()) : msg.sender, account);
    /// #if_succeeds "is non-reentant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isImpersonationInProgress());
    /// #if_succeeds "the vault is present in the controller set 1" old(accountControllers[account].numElements) < 20 ==> accountControllers[account].contains(vault);
    /// #if_succeeds "number of vaults is equal to the controller array length 1" accountControllers[account].numElements == accountControllers[account].get().length;
    /// #if_succeeds "controller cannot be CVC" vault != address(this);
    function enableController(
        address account,
        address vault
    ) public payable virtual override {
        super.enableController(account, vault);
    }

    /// #if_succeeds "is non-reentant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isImpersonationInProgress());
    /// #if_succeeds "the vault is not present the collateral set 2" !accountControllers[account].contains(msg.sender);
    /// #if_succeeds "number of vaults is equal to the collateral array length 2" accountControllers[account].numElements == accountControllers[account].get().length;
    function disableController(
        address account
    ) public payable virtual override {
        super.disableController(account);
    }

    /// #if_succeeds "only the account owner or operator can call this" ownerOrOperator(address(this) == msg.sender ? old(executionContext.getOnBehalfOfAccount()) : msg.sender, onBehalfOfAccount);
    /// #if_succeeds "is non-reentant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isImpersonationInProgress());
    /// #if_succeeds "the target can neither be this contract nor ERC-1810 registry" targetContract != address(this) && targetContract != ERC1820_REGISTRY;
    function call(
        address targetContract,
        address onBehalfOfAccount,
        bytes calldata data
    )
        public
        payable
        virtual
        override
        returns (bool success, bytes memory result)
    {
        (success, result) = super.call(targetContract, onBehalfOfAccount, data);
    }

    /// #if_succeeds "is non-reentant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isImpersonationInProgress());
    /// #if_succeeds "only enabled controller can call into enabled collateral" getControllers(onBehalfOfAccount).length == 1 && isControllerEnabled(onBehalfOfAccount, msg.sender) && isCollateralEnabled(onBehalfOfAccount, targetContract);
    /// #if_succeeds "the target cannot be this contract" targetContract != address(this);
    function impersonate(
        address targetContract,
        address onBehalfOfAccount,
        bytes calldata data
    )
        public
        payable
        virtual
        override
        returns (bool success, bytes memory result)
    {
        return super.impersonate(targetContract, onBehalfOfAccount, data);
    }

    /// #if_succeeds "is non-reentant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isImpersonationInProgress());
    function permit(
        address signer,
        uint nonceNamespace,
        uint nonce,
        uint deadline,
        bytes calldata data,
        bytes calldata signature
    ) public payable virtual override {
        super.permit(signer, nonceNamespace, nonce, deadline, data, signature);
    }

    /// #if_succeeds "is non-reentant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isImpersonationInProgress());
    /// #if_succeeds "batch depth doesn't change pre- and post- execution" old(EC.unwrap(executionContext)) == EC.unwrap(executionContext);
    /// #if_succeeds "checks are properly executed 1" !old(executionContext.isInBatch()) && old(accountStatusChecks.numElements) > 0 ==> accountStatusChecks.numElements == 0;
    /// #if_succeeds "checks are properly executed 2" !old(executionContext.isInBatch()) && old(vaultStatusChecks.numElements) > 0 ==> vaultStatusChecks.numElements == 0;
    /// #if_succeeds "batch depth is in range" !old(executionContext.isBatchDepthExceeded());
    function batch(BatchItem[] calldata items) public payable virtual override {
        super.batch(items);
    }

    /// #if_succeeds "this function must always revert" false;
    function batchRevert(
        BatchItem[] calldata items
    )
        public
        payable
        virtual
        override
        returns (
            BatchItemResult[] memory batchItemsResult,
            BatchItemResult[] memory accountsStatusResult,
            BatchItemResult[] memory vaultsStatusResult
        )
    {
        return super.batchRevert(items);
    }

    /// #if_succeeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeeds "account is never added to the set or it's still present" old(accountStatusChecks.contains(account)) == accountStatusChecks.contains(account);
    function checkAccountStatus(
        address account
    ) public payable virtual override returns (bool isValid) {
        return super.checkAccountStatus(account);
    }

    /// #if_succeeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeeds "accounts are never added to the set or they're still present" old(accountStatusChecks.get().length) == accountStatusChecks.get().length;
    function checkAccountsStatus(
        address[] calldata accounts
    ) public payable virtual override returns (bool[] memory isValid) {
        return super.checkAccountsStatus(accounts);
    }

    /// #if_succeeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeeds "account is added to the set only if checks deferred" old(executionContext.isInBatch()) ==> accountStatusChecks.contains(account);
    function requireAccountStatusCheck(
        address account
    ) public payable virtual override {
        super.requireAccountStatusCheck(account);
    }

    /// #if_succeeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeeds "accounts are added to the set only if checks deferred" old(executionContext.isInBatch()) ==> forall(uint i in 0...accounts.length-1) accountStatusChecks.contains(accounts[i]);
    function requireAccountsStatusCheck(
        address[] calldata accounts
    ) public payable virtual override {
        super.requireAccountsStatusCheck(accounts);
    }

    /// #if_succeeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeeds "account is never added to the set or it's removed if previously present" !accountStatusChecks.contains(account);
    function requireAccountStatusCheckNow(
        address account
    ) public payable virtual override {
        super.requireAccountStatusCheckNow(account);
    }

    /// #if_succeeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeeds "accounts are never added to the set or they're removed if previously present" forall(uint i in 0...accounts.length-1) !accountStatusChecks.contains(accounts[i]);
    function requireAccountsStatusCheckNow(
        address[] calldata accounts
    ) public payable virtual override {
        super.requireAccountsStatusCheckNow(accounts);
    }

    /// #if_succeeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeeds "the set is empty after calling this" accountStatusChecks.numElements == 0;
    function requireAllAccountsStatusCheckNow()
        public
        payable
        virtual
        override
    {
        super.requireAllAccountsStatusCheckNow();
    }

    /// #if_succeeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeeds "account is never present in the set after calling this" !accountStatusChecks.contains(account);
    function forgiveAccountStatusCheck(
        address account
    ) public payable virtual override {
        super.forgiveAccountStatusCheck(account);
    }

    /// #if_succeeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeeds "accounts are never present in the set after calling this" forall(uint i in 0...accounts.length-1) !accountStatusChecks.contains(accounts[i]);
    function forgiveAccountsStatusCheck(
        address[] calldata accounts
    ) public payable virtual override {
        super.forgiveAccountsStatusCheck(accounts);
    }

    /// #if_succeeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeeds "vault is added to the set only if checks deferred" old(executionContext.isInBatch()) ==> vaultStatusChecks.contains(msg.sender);
    function requireVaultStatusCheck() public payable virtual override {
        super.requireVaultStatusCheck();
    }

    /// #if_succeeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeeds "vault is never added to the set or it's removed if previously present" !vaultStatusChecks.contains(vault);
    function requireVaultStatusCheckNow(
        address vault
    ) public payable virtual override {
        super.requireVaultStatusCheckNow(vault);
    }

    /// #if_succeeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeeds "vaults are never added to the set or they're removed if previously present" forall(uint i in 0...vaults.length-1) !vaultStatusChecks.contains(vaults[i]);
    function requireVaultsStatusCheckNow(
        address[] calldata vaults
    ) public payable virtual override {
        super.requireVaultsStatusCheckNow(vaults);
    }

    /// #if_succeeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeeds "the set is empty after calling this" vaultStatusChecks.numElements == 0;
    function requireAllVaultsStatusCheckNow() public payable virtual override {
        super.requireAllVaultsStatusCheckNow();
    }

    /// #if_succeeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeeds "vault is never present in the set after calling this" !vaultStatusChecks.contains(msg.sender);
    function forgiveVaultStatusCheck() public payable virtual override {
        super.forgiveVaultStatusCheck();
    }

    /// #if_succeeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeeds "account is added to the set only if checks deferred" executionContext.isInBatch() ==> accountStatusChecks.contains(account);
    /// #if_succeeds "vault is added to the set only if checks deferred" executionContext.isInBatch() ==> vaultStatusChecks.contains(msg.sender);
    function requireAccountAndVaultStatusCheck(
        address account
    ) public payable virtual override {
        super.requireAccountAndVaultStatusCheck(account);
    }

    /// #if_succeeds "impersonate reentrancy guard must be locked" executionContext.isImpersonationInProgress();
    function impersonateInternal(
        address targetContract,
        address onBehalfOfAccount,
        uint value,
        bytes calldata data
    ) internal virtual override returns (bool success, bytes memory result) {
        return
            super.impersonateInternal(
                targetContract,
                onBehalfOfAccount,
                value,
                data
            );
    }

    /// #if_succeeds "must be in a batch" executionContext.isInBatch();
    function batchInternal(
        BatchItem[] calldata items,
        bool returnResult
    ) internal override returns (BatchItemResult[] memory batchItemsResult) {
        return super.batchInternal(items, returnResult);
    }

    /// #if_succeeds "must have at most one controller" accountControllers[account].numElements <= 1;
    function checkAccountStatusInternal(
        address account
    ) internal override returns (bool isValid, bytes memory data) {
        return super.checkAccountStatusInternal(account);
    }

    /// #if_succeeds "checks reentrancy guard must be locked" executionContext.areChecksInProgress();
    /// #if_succeeds "appropriate set must be empty after execution 1" setType == SetType.Account ==> accountStatusChecks.numElements == 0;
    /// #if_succeeds "appropriate set must be empty after execution 2" setType == SetType.Vault ==> vaultStatusChecks.numElements == 0;
    /// #if_succeeds "execution context stays untouched" old(EC.unwrap(executionContext)) == EC.unwrap(executionContext);
    function checkStatusAll(
        SetType setType,
        bool returnResult
    ) internal override returns (BatchItemResult[] memory result) {
        return super.checkStatusAll(setType, returnResult);
    }
}
