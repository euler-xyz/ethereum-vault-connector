// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "../CreditVaultConnector.sol";

/// #define ownerOrOperator(address msgSender, address account) bool = (ownerLookup[uint152(uint160(account) >> 8)].owner == msgSender || (ownerLookup[uint152(uint160(account) >> 8)].owner == address(0) && (uint160(msgSender) | 0xFF) == (uint160(account) | 0xFF));) || operatorLookup[account][msgSender].authorizationExpiryTimestamp >= block.timestamp;

/// #if_succeeds "batch depth is in INIT state" !old(executionContext.isInBatch()) && !executionContext.isInBatch();
/// #if_succeeds "onBehalfOfAccount is zero address" old(executionContext.getOnBehalfOfAccount()) == address(0) && executionContext.getOnBehalfOfAccount() == address(0);
/// #if_succeeds "checks lock is false" !old(executionContext.areChecksInProgress()) && !executionContext.areChecksInProgress();
/// #if_succeeds "impersonate lock is false" !old(executionContext.isImpersonationInProgress()) && !executionContext.isImpersonationInProgress();
/// #if_succeeds "account status checks set is empty 1" old(accountStatusChecks.numElements) == 0 && accountStatusChecks.numElements == 0;
/// #if_succeeds "account status checks set is empty 2" old(accountStatusChecks.firstElement) == address(0) && accountStatusChecks.firstElement == address(0);
/// #if_succeeds "account status checks set is empty 3" forall(uint i in 0...20) accountStatusChecks.elements[i].value == address(0);
/// #if_succeeds "vault status checks set is empty 1" old(vaultStatusChecks.numElements) == 0 && vaultStatusChecks.numElements == 0;
/// #if_succeeds "vault status checks set is empty 2" old(vaultStatusChecks.firstElement) == address(0) && vaultStatusChecks.firstElement == address(0);
/// #if_succeeds "vault status checks set is empty 3" forall(uint i in 0...20) vaultStatusChecks.elements[i].value == address(0);
/// #invariant "account status checks set has at most 20 elements" accountStatusChecks.numElements <= 20;
/// #invariant "vault status checks set has at most 20 elements" vaultStatusChecks.numElements <= 20;
/// #if_succeeds "each account has at most 1 controller" forall(uint i in ownerLookup) forall(uint j in 0...256) accountControllers[address(uint160((i << 8) ^ j))].numElements <= 1;
contract CreditVaultConnectorScribble is CreditVaultConnector {
    using ExecutionContext for EC;
    using Set for SetStorage;

    /// #if_succeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
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

    /// #if_succeds "only the account owner or operator can call this" ownerOrOperator(msg.sender, account);
    /// #if_succeeds "operator is not a sub-account of the owner" !haveCommonOwner(operator, ownerLookup[getPrefixInternal(account)].owner);
    /// #if_succeeds "last signature timestamp is not updated" old(operatorLookup[account][operator].lastSignatureTimestamp) == operatorLookup[account][operator].lastSignatureTimestamp;
    function setAccountOperator(
        address account,
        address operator,
        uint40 expiryTimestamp
    ) public payable virtual override {
        super.setAccountOperator(account, operator, expiryTimestamp);
    }

    /// #if_succeeds "operator is not a sub-account of the owner" !haveCommonOwner(operator, ownerLookup[getPrefixInternal(account)].owner);
    /// #if_succeeds "last signature timestamp is updated" operatorLookup[account][operator].lastSignatureTimestamp == block.timestamp;
    function setAccountOperatorPermitECDSA(
        address account,
        address operator,
        uint40 authExpiryTimestamp,
        uint40 signatureTimestamp,
        uint40 signatureDeadlineTimestamp,
        bytes calldata signature
    ) public payable virtual override {
        super.setAccountOperatorPermitECDSA(
            account,
            operator,
            authExpiryTimestamp,
            signatureTimestamp,
            signatureDeadlineTimestamp,
            signature
        );
    }

    /// #if_succeeds "operator is not a sub-account of the owner" !haveCommonOwner(operator, ownerLookup[getPrefixInternal(account)].owner);
    /// #if_succeeds "last signature timestamp is updated" operatorLookup[account][operator].lastSignatureTimestamp == block.timestamp;
    function setAccountOperatorPermitERC1271(
        address account,
        address operator,
        uint40 authExpiryTimestamp,
        uint40 signatureTimestamp,
        uint40 signatureDeadlineTimestamp,
        bytes calldata signature,
        address erc1271Signer
    ) public payable virtual override {
        super.setAccountOperatorPermitERC1271(
            account,
            operator,
            authExpiryTimestamp,
            signatureTimestamp,
            signatureDeadlineTimestamp,
            signature,
            erc1271Signer
        );
    }

    /// #if_succeeds "last signature timestamp is updated" ownerLookup[uint152(uint160(msg.sender) >> 8)].lastSignatureTimestamp == block.timestamp;
    function invalidateAllPermits() public payable virtual override {
        super.invalidateAllPermits();
    }

    /// #if_succeeds "only the account owner can call this" ownerLookup[uint152(uint160(account) >> 8)].owner == msg.sender || (ownerLookup[uint152(uint160(account) >> 8)].owner == address(0) && (uint160(msg.sender) | 0xFF) == (uint160(account) | 0xFF));
    /// #if_succeeds "last signature timestamp is updated" operatorLookup[account][operator].lastSignatureTimestamp == block.timestamp;
    function invalidateAccountOperatorPermits(
        address account,
        address operator
    ) public payable virtual override {
        super.invalidateAccountOperatorPermits(account, operator);
    }

    /// #if_succeds "only the account owner or operator can call this" ownerOrOperator(msg.sender, account);
    /// #if_succeds "is non-reentant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isImpersonationInProgress());
    /// #if_succeeds "the vault is present in the collateral set 1" old(accountCollaterals[account].numElements) < 20 ==> accountCollaterals[account].contains(vault);
    /// #if_succeeds "number of vault is equal to the collateral array length 1" accountCollaterals[account].numElements == accountCollaterals[account].get().length;
    function enableCollateral(
        address account,
        address vault
    ) public payable virtual override {
        super.enableCollateral(account, vault);
    }

    /// #if_succeds "only the account owner or operator can call this" ownerOrOperator(msg.sender, account);
    /// #if_succeds "is non-reentant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isImpersonationInProgress());
    /// #if_succeeds "the vault is not present the collateral set 2" !accountCollaterals[account].contains(vault);
    /// #if_succeeds "number of vaults is equal to the collateral array length 2" accountCollaterals[account].numElements == accountCollaterals[account].get().length;
    function disableCollateral(
        address account,
        address vault
    ) public payable virtual override {
        super.disableCollateral(account, vault);
    }

    /// #if_succeds "only the account owner or operator can call this" ownerOrOperator(msg.sender, account);
    /// #if_succeds "is non-reentant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isImpersonationInProgress());
    /// #if_succeeds "the vault is present in the controller set 1" old(accountControllers[account].numElements) < 20 ==> accountControllers[account].contains(vault);
    /// #if_succeeds "number of vault is equal to the controller array length 1" accountControllers[account].numElements == accountControllers[account].get().length;
    function enableController(
        address account,
        address vault
    ) public payable virtual override {
        super.enableController(account, vault);
    }

    /// #if_succeds "is non-reentant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isImpersonationInProgress());
    /// #if_succeeds "the vault is not present the collateral set 2" !accountControllers[account].contains(msg.sender);
    /// #if_succeeds "number of vaults is equal to the collateral array length 2" accountControllers[account].numElements == accountControllers[account].get().length;
    function disableController(
        address account
    ) public payable virtual override {
        super.disableController(account);
    }

    /// #if_succeds "only the account owner or operator can call this" ownerOrOperator(msg.sender, onBehalfOfAccount);
    /// #if_succeds "is non-reentant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isImpersonationInProgress());
    /// #if_succeds "the target can neither be this contract nor ERC-1810 registry" targetContract != address(this) && targetContract != ERC1820_REGISTRY;
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

    /// #if_succeds "is non-reentant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isImpersonationInProgress());
    /// #if_succeds "only enabled controller can call into enabled collateral" getControllers(onBehalfOfAccount).length == 1 && isControllerEnabled(onBehalfOfAccount, msg.sender) && isCollateralEnabled(onBehalfOfAccount, targetContract);
    /// #if_succeds "the target cannot be this contract" targetContract != address(this);
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

    /// #if_succeds "is non-reentant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isImpersonationInProgress());
    /// #if_succeds "batch depth doesn't change pre- and post- execution" old(EC.unwrap(executionContext)) == EC.unwrap(executionContext);
    /// #if_succeds "checks are properly executed 1" !executionContext.isInBatch() && old(accountStatusChecks.numElements) > 0 ==> accountStatusChecks.numElements == 0;
    /// #if_succeds "checks are properly executed 2" !executionContext.isInBatch() && old(vaultStatusChecks.numElements) > 0 ==> vaultStatusChecks.numElements == 0;
    function batch(BatchItem[] calldata items) public payable virtual override {
        super.batch(items);
    }

    /// #if_succeds "this function must always revert" false;
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

    /// #if_succeds "this function must always revert" false;
    function batchSimulation(
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
        return super.batchSimulation(items);
    }

    /// #if_succeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeds "account is never added to the set or it's still present" old(accountStatusChecks.contains(account)) == accountStatusChecks.contains(account);
    function checkAccountStatus(
        address account
    ) public payable virtual override returns (bool isValid) {
        return super.checkAccountStatus(account);
    }

    /// #if_succeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeds "accounts are never added to the set or they're still present" forall(address i in accounts) old(accountStatusChecks.contains(i)) == accountStatusChecks.contains(i);
    function checkAccountsStatus(
        address[] calldata accounts
    ) public payable virtual override returns (bool[] memory isValid) {
        return super.checkAccountsStatus(accounts);
    }

    /// #if_succeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeds "account is added to the set only if checks deferred" executionContext.isInBatch() ==> accountStatusChecks.contains(account);
    function requireAccountStatusCheck(
        address account
    ) public payable virtual override {
        super.requireAccountStatusCheck(account);
    }

    /// #if_succeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeds "accounts are added to the set only if checks deferred" executionContext.isInBatch() ==> forall(address i in accounts) accountStatusChecks.contains(i);
    function requireAccountsStatusCheck(
        address[] calldata accounts
    ) public payable virtual override {
        super.requireAccountsStatusCheck(accounts);
    }

    /// #if_succeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeds "account is never added to the set or it's removed if previously present" !accountStatusChecks.contains(account);
    function requireAccountStatusCheckNow(
        address account
    ) public payable virtual override {
        super.requireAccountStatusCheckNow(account);
    }

    /// #if_succeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeds "accounts are never added to the set or they're removed if previously present" forall(address i in accounts) !accountStatusChecks.contains(i);
    function requireAccountsStatusCheckNow(
        address[] calldata accounts
    ) public payable virtual override {
        super.requireAccountsStatusCheckNow(accounts);
    }

    /// #if_succeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeds "the set is empty after calling this" accountStatusChecks.numElements == 0;
    function requireAllAccountsStatusCheckNow()
        public
        payable
        virtual
        override
    {
        super.requireAllAccountsStatusCheckNow();
    }

    /// #if_succeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeds "account is never present in the set after calling this" !accountStatusChecks.contains(account);
    function forgiveAccountStatusCheck(
        address account
    ) public payable virtual override {
        super.forgiveAccountStatusCheck(account);
    }

    /// #if_succeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeds "accounts are never present in the set after calling this" forall(address i in accounts) !accountStatusChecks.contains(i);
    function forgiveAccountsStatusCheck(
        address[] calldata accounts
    ) public payable virtual override {
        super.forgiveAccountsStatusCheck(accounts);
    }

    /// #if_succeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeds "vault is added to the set only if checks deferred" executionContext.isInBatch() ==> vaultStatusChecks.contains(msg.sender);
    function requireVaultStatusCheck() public payable virtual override {
        super.requireVaultStatusCheck();
    }

    /// #if_succeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeds "vault is never added to the set or it's removed if previously present" !vaultStatusChecks.contains(vault);
    function requireVaultStatusCheckNow(
        address vault
    ) public payable virtual override {
        super.requireVaultStatusCheckNow(vault);
    }

    /// #if_succeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeds "vaults are never added to the set or they're removed if previously present" forall(address i in vaults) !vaultStatusChecks.contains(i);
    function requireVaultsStatusCheckNow(
        address[] calldata vaults
    ) public payable virtual override {
        super.requireVaultsStatusCheckNow(vaults);
    }

    /// #if_succeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeds "the set is empty after calling this" vaultStatusChecks.numElements == 0;
    function requireAllVaultsStatusCheckNow() public payable virtual override {
        super.requireAllVaultsStatusCheckNow();
    }

    /// #if_succeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeds "vault is never present in the set after calling this" !vaultStatusChecks.contains(msg.sender);
    function forgiveVaultStatusCheck() public payable override {
        super.forgiveVaultStatusCheck();
    }

    /// #if_succeds "is checks non-reentant" !old(executionContext.areChecksInProgress());
    /// #if_succeds "account is added to the set only if checks deferred" executionContext.isInBatch() ==> accountStatusChecks.contains(account);
    /// #if_succeds "vault is added to the set only if checks deferred" executionContext.isInBatch() ==> vaultStatusChecks.contains(msg.sender);
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
    ) internal override returns (bool success, bytes memory result) {
        return
            super.impersonateInternal(
                targetContract,
                onBehalfOfAccount,
                value,
                data
            );
    }

    /// #if_succeeds "batch depth is in range" !executionContext.isBatchDepthExceeded();
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
    /// #if_succeeds "execution context stays untouched" old(keccak256(abi.encode(EC.unwrap(executionContext)))) == keccak256(abi.encode(EC.unwrap(executionContext)));
    function checkStatusAll(
        SetType setType,
        bool returnResult
    ) internal override returns (BatchItemResult[] memory result) {
        return super.checkStatusAll(setType, returnResult);
    }

    /// #if_succeeds "on behalf of account must be properly set" old(executionContext.getOnBehalfOfAccount()) == onBehalfOfAccount && executionContext.getOnBehalfOfAccount() == onBehalfOfAccount;
    function callTargetContractInternal(
        address targetContract,
        address onBehalfOfAccount,
        uint value,
        bytes calldata data
    ) internal virtual override returns (bool success, bytes memory result) {
        return
            super.callTargetContractInternal(
                targetContract,
                onBehalfOfAccount,
                value,
                data
            );
    }
}
