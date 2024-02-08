// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.19;

import "../../src/EthereumVaultConnector.sol";

/// #if_succeeds "on behalf account state doesn't change" old(executionContext.getOnBehalfOfAccount()) == executionContext.getOnBehalfOfAccount();
/// #if_succeeds "checks deferred state doesn't change" old(executionContext.areChecksDeferred()) == executionContext.areChecksDeferred();
/// #if_succeeds "checks in progress state doesn't change" old(executionContext.areChecksInProgress()) == executionContext.areChecksInProgress();
/// #if_succeeds "control collateral in progress state doesn't change" old(executionContext.isControlCollateralInProgress()) == executionContext.isControlCollateralInProgress();
/// #if_succeeds "operator authenticated state doesn't change" old(executionContext.isOperatorAuthenticated()) == executionContext.isOperatorAuthenticated();
/// #if_succeeds "simulation in progress state doesn't change" old(executionContext.isSimulationInProgress()) == executionContext.isSimulationInProgress();
/// #if_succeeds "on behalf of account is zero when checks in progress" executionContext.areChecksInProgress() ==> executionContext.getOnBehalfOfAccount() == address(0);
/// #if_succeeds "account status checks set is empty 1" !old(executionContext.areChecksDeferred()) ==> old(accountStatusChecks.numElements) == 0 && accountStatusChecks.numElements == 0;
/// #if_succeeds "account status checks set is empty 2" !old(executionContext.areChecksDeferred()) ==> old(accountStatusChecks.firstElement) == address(0) && accountStatusChecks.firstElement == address(0);
/// #if_succeeds "account status checks set is empty 3" !old(executionContext.areChecksDeferred()) ==> forall(uint256 i in 0...20) accountStatusChecks.elements[i].value == address(0);
/// #if_succeeds "vault status checks set is empty 1" !old(executionContext.areChecksDeferred()) ==> old(vaultStatusChecks.numElements) == 0 && vaultStatusChecks.numElements == 0;
/// #if_succeeds "vault status checks set is empty 2" !old(executionContext.areChecksDeferred()) ==> old(vaultStatusChecks.firstElement) == address(0) && vaultStatusChecks.firstElement == address(0);
/// #if_succeeds "vault status checks set is empty 3" !old(executionContext.areChecksDeferred()) ==> forall(uint256 i in 0...20) vaultStatusChecks.elements[i].value == address(0);
/// #if_succeeds "each account has at most 1 controller" !old(executionContext.areChecksDeferred()) ==> forall(uint256 i in ownerLookup) forall(uint256 j in 0...256) accountControllers[address(uint160((i << 8) ^ j))].numElements <= 1;
/// #invariant "account status checks set has at most 20 elements" accountStatusChecks.numElements <= 20;
/// #invariant "vault status checks set has at most 20 elements" vaultStatusChecks.numElements <= 20;
contract EthereumVaultConnectorScribble is EthereumVaultConnector {
    using ExecutionContext for EC;
    using Set for SetStorage;

    /// #if_succeeds "is non-reentrant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isControlCollateralInProgress());
    /// #if_succeeds "the vault is present in the collateral set 1" old(accountCollaterals[account].numElements) < 20 ==> accountCollaterals[account].contains(vault);
    /// #if_succeeds "number of vaults is equal to the collateral array length 1" accountCollaterals[account].numElements == accountCollaterals[account].get().length;
    /// #if_succeeds "collateral cannot be EVC" vault != address(this);
    function enableCollateral(address account, address vault) public payable virtual override {
        super.enableCollateral(account, vault);
    }

    /// #if_succeeds "is non-reentrant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isControlCollateralInProgress());
    /// #if_succeeds "the vault is not present the collateral set 2" !accountCollaterals[account].contains(vault);
    /// #if_succeeds "number of vaults is equal to the collateral array length 2" accountCollaterals[account].numElements == accountCollaterals[account].get().length;
    function disableCollateral(address account, address vault) public payable virtual override {
        super.disableCollateral(account, vault);
    }

    /// #if_succeeds "is non-reentrant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isControlCollateralInProgress());
    // #if_succeeds "the vaults are swapped" not possible with scribble due to out-of-bounds error
    /// #if_succeeds "number of vaults in the set doesn't change" old(accountCollaterals[account].numElements) == accountCollaterals[account].numElements;
    function reorderCollaterals(address account, uint8 index1, uint8 index2) public payable virtual override {
        super.reorderCollaterals(account, index1, index2);
    }

    /// #if_succeeds "is non-reentrant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isControlCollateralInProgress());
    /// #if_succeeds "the vault is present in the controller set 1" old(accountControllers[account].numElements) < 20 ==> accountControllers[account].contains(vault);
    /// #if_succeeds "number of vaults is equal to the controller array length 1" accountControllers[account].numElements == accountControllers[account].get().length;
    /// #if_succeeds "controller cannot be EVC" vault != address(this);
    function enableController(address account, address vault) public payable virtual override {
        super.enableController(account, vault);
    }

    /// #if_succeeds "is non-reentrant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isControlCollateralInProgress());
    /// #if_succeeds "the vault is not present the collateral set 2" !accountControllers[account].contains(msg.sender);
    /// #if_succeeds "number of vaults is equal to the collateral array length 2" accountControllers[account].numElements == accountControllers[account].get().length;
    function disableController(address account) public payable virtual override {
        super.disableController(account);
    }

    /// #if_succeeds "is non-reentrant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isControlCollateralInProgress());
    function permit(
        address signer,
        uint256 nonceNamespace,
        uint256 nonce,
        uint256 deadline,
        uint256 value,
        bytes calldata data,
        bytes calldata signature
    ) public payable virtual override {
        super.permit(signer, nonceNamespace, nonce, deadline, value, data, signature);
    }

    /// #if_succeeds "is non-reentrant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isControlCollateralInProgress());
    /// #if_succeeds "checks are properly executed 1" !old(executionContext.areChecksDeferred()) && old(accountStatusChecks.numElements) > 0 ==> accountStatusChecks.numElements == 0;
    /// #if_succeeds "checks are properly executed 2" !old(executionContext.areChecksDeferred()) && old(vaultStatusChecks.numElements) > 0 ==> vaultStatusChecks.numElements == 0;
    function call(
        address targetContract,
        address onBehalfOfAccount,
        uint256 value,
        bytes calldata data
    ) public payable virtual override returns (bytes memory result) {
        return super.call(targetContract, onBehalfOfAccount, value, data);
    }

    /// #if_succeeds "is non-reentrant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isControlCollateralInProgress());
    /// #if_succeeds "only enabled controller can call into enabled collateral" getControllers(onBehalfOfAccount).length == 1 && isControllerEnabled(onBehalfOfAccount, msg.sender) && isCollateralEnabled(onBehalfOfAccount, targetCollateral);
    /// #if_succeeds "the target cannot be this contract" targetCollateral != address(this);
    /// #if_succeeds "checks are properly executed 1" !old(executionContext.areChecksDeferred()) && old(accountStatusChecks.numElements) > 0 ==> accountStatusChecks.numElements == 0;
    /// #if_succeeds "checks are properly executed 2" !old(executionContext.areChecksDeferred()) && old(vaultStatusChecks.numElements) > 0 ==> vaultStatusChecks.numElements == 0;
    function controlCollateral(
        address targetCollateral,
        address onBehalfOfAccount,
        uint256 value,
        bytes calldata data
    ) public payable virtual override returns (bytes memory result) {
        return super.controlCollateral(targetCollateral, onBehalfOfAccount, value, data);
    }

    /// #if_succeeds "is non-reentrant" !old(executionContext.areChecksInProgress()) && !old(executionContext.isControlCollateralInProgress());
    /// #if_succeeds "checks are properly executed 1" !old(executionContext.areChecksDeferred()) && old(accountStatusChecks.numElements) > 0 ==> accountStatusChecks.numElements == 0;
    /// #if_succeeds "checks are properly executed 2" !old(executionContext.areChecksDeferred()) && old(vaultStatusChecks.numElements) > 0 ==> vaultStatusChecks.numElements == 0;
    function batch(BatchItem[] calldata items) public payable virtual override {
        super.batch(items);
    }

    /// #if_succeeds "this function must always revert" false;
    function batchRevert(BatchItem[] calldata items) public payable virtual override {
        super.batchRevert(items);
    }

    /// #if_succeeds "is checks non-reentrant" !old(executionContext.areChecksInProgress());
    /// #if_succeeds "account is added to the set only if checks deferred" old(executionContext.areChecksDeferred()) ==> accountStatusChecks.contains(account);
    function requireAccountStatusCheck(address account) public payable virtual override {
        super.requireAccountStatusCheck(account);
    }

    /// #if_succeeds "is checks non-reentrant" !old(executionContext.areChecksInProgress());
    /// #if_succeeds "account is never present in the set after calling this" !accountStatusChecks.contains(account);
    function forgiveAccountStatusCheck(address account) public payable virtual override {
        super.forgiveAccountStatusCheck(account);
    }

    /// #if_succeeds "is checks non-reentrant" !old(executionContext.areChecksInProgress());
    /// #if_succeeds "vault is added to the set only if checks deferred" old(executionContext.areChecksDeferred()) ==> vaultStatusChecks.contains(msg.sender);
    function requireVaultStatusCheck() public payable virtual override {
        super.requireVaultStatusCheck();
    }

    /// #if_succeeds "is checks non-reentrant" !old(executionContext.areChecksInProgress());
    /// #if_succeeds "vault is never present in the set after calling this" !vaultStatusChecks.contains(msg.sender);
    function forgiveVaultStatusCheck() public payable virtual override {
        super.forgiveVaultStatusCheck();
    }

    /// #if_succeeds "is checks non-reentrant" !old(executionContext.areChecksInProgress());
    /// #if_succeeds "account is added to the set only if checks deferred" executionContext.areChecksDeferred() ==> accountStatusChecks.contains(account);
    /// #if_succeeds "vault is added to the set only if checks deferred" executionContext.areChecksDeferred() ==> vaultStatusChecks.contains(msg.sender);
    function requireAccountAndVaultStatusCheck(address account) public payable virtual override {
        super.requireAccountAndVaultStatusCheck(account);
    }

    /// #if_succeeds "checks must be deferred if not in permit" bytes4(msg.data) != this.permit.selector ==> executionContext.areChecksDeferred();
    /// #if_succeeds "control collateral reentrancy guard must be locked if necessary" bytes4(msg.data) == this.controlCollateral.selector ==> executionContext.isControlCollateralInProgress();
    function callWithContextInternal(
        address targetContract,
        address onBehalfOfAccount,
        uint256 value,
        bytes calldata data
    ) internal virtual override returns (bool success, bytes memory result) {
        return super.callWithContextInternal(targetContract, onBehalfOfAccount, value, data);
    }

    /// #if_succeeds "must have at most one controller" accountControllers[account].numElements <= 1;
    function checkAccountStatusInternal(address account) internal override returns (bool isValid, bytes memory data) {
        return super.checkAccountStatusInternal(account);
    }

    /// #if_succeeds "checks reentrancy guard must be locked" executionContext.areChecksInProgress();
    /// #if_succeeds "appropriate set must be empty after execution 1" setType == SetType.Account ==> accountStatusChecks.numElements == 0;
    /// #if_succeeds "appropriate set must be empty after execution 2" setType == SetType.Vault ==> vaultStatusChecks.numElements == 0;
    /// #if_succeeds "execution context stays untouched" old(EC.unwrap(executionContext)) == EC.unwrap(executionContext);
    function checkStatusAll(SetType setType) internal override {
        return super.checkStatusAll(setType);
    }

    /// #if_succeeds "checks reentrancy guard must be locked" executionContext.areChecksInProgress();
    /// #if_succeeds "appropriate set must be empty after execution 1" setType == SetType.Account ==> accountStatusChecks.numElements == 0;
    /// #if_succeeds "appropriate set must be empty after execution 2" setType == SetType.Vault ==> vaultStatusChecks.numElements == 0;
    /// #if_succeeds "execution context stays untouched" old(EC.unwrap(executionContext)) == EC.unwrap(executionContext);
    function checkStatusAllWithResult(SetType setType) internal override returns (StatusCheckResult[] memory result) {
        return super.checkStatusAllWithResult(setType);
    }
}
