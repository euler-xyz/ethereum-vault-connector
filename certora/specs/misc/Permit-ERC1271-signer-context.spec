// The EVC checks a permit's ERC-1271 signature before it sets the permit's
// execution context, so the signer runs in the execution context of the
// permit's caller. Inside a call() whose target is the caller, that context
// holds an account the caller chose without authentication (CER-23).

using PermitCaller as permitCaller;
using ContextSigner as contextSigner;

methods {
    function getExecutionContextOnBehalfOfAccount() external returns (address) envfree;
    function getRawExecutionContext() external returns (uint256) envfree;
    function getExecutionContextDefault() external returns (uint256) envfree;
    function getAddressPrefix(address) external returns (bytes19) envfree;
    function haveCommonOwner(address, address) external returns (bool) envfree;
    function isAccountOperatorAuthorized(address, address) external returns (bool) envfree;
    function PermitCaller.signer() external returns (address) envfree;
    function ContextSigner.authorizedAccount() external returns (address) envfree;

    // Routes the EVC's low-level calls: the call() callback to the caller and
    // the ERC-1271 staticcall to the signer.
    unresolved external in _._ => DISPATCH [
        PermitCaller.onEVCCall(),
        ContextSigner.isValidSignature(bytes32, bytes)
    ] default NONDET;

    // The signers here are contracts, for which no ECDSA key exists.
    function EthereumVaultConnector.recoverECDSASigner(bytes32, bytes memory) internal returns (address) => noECDSASigner();

    function EthereumVaultConnector.requireAccountStatusCheckInternal(address account) internal => NONDET;
    function EthereumVaultConnector.requireVaultStatusCheckInternal(address vault) internal => NONDET;
    function EthereumVaultConnector.checkStatusAll(TransientStorage.SetType setType) internal => NONDET;
}

function noECDSASigner() returns address {
    address none;
    require none == 0;
    return none;
}

persistent ghost address watchedSigner;
persistent ghost bytes19 watchedPrefix;
persistent ghost bool signerCalled;
persistent ghost address accountSeenBySigner;
persistent ghost bool signatureAccepted;

hook STATICCALL(uint g, address addr, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc {
    if (executingContract == currentContract && addr == watchedSigner) {
        signerCalled = true;
        accountSeenBySigner = getExecutionContextOnBehalfOfAccount();
    }
}

// permit() consumes the signer's nonce only after accepting the signature.
hook Sstore EthereumVaultConnectorHarness.nonceLookup[KEY bytes19 prefix][KEY uint256 nonceNamespace] uint256 newNonce {
    if (prefix == watchedPrefix) {
        signatureAccepted = true;
    }
}

rule erc1271_signer_sees_execution_context_of_permit_caller {
    env e;
    address signer;
    address sender;
    uint256 nonceNamespace;
    uint256 nonce;
    uint256 deadline;
    uint256 value;
    bytes data;
    bytes signature;

    address accountOfCaller = getExecutionContextOnBehalfOfAccount();
    require watchedSigner == signer;
    require !signerCalled;

    permit@withrevert(e, signer, sender, nonceNamespace, nonce, deadline, value, data, signature);

    assert signerCalled => accountSeenBySigner == accountOfCaller;
}

// A contract calls call() with itself as the target and an account it has no
// rights over, and calls permit() from the callback. A signer that trusts the
// account the EVC reports approves the permit, so the EVC goes on to execute
// the permit's data on behalf of the signer.
rule callback_gets_erc1271_permit_approved_for_chosen_account {
    env e;
    address account;
    bytes data;

    require getRawExecutionContext() == getExecutionContextDefault();
    require e.msg.sender == permitCaller;
    require permitCaller.signer() == contextSigner;
    require contextSigner.authorizedAccount() == account;
    require account != 0 && account != contextSigner;
    require !haveCommonOwner(account, permitCaller);
    require !isAccountOperatorAuthorized(account, permitCaller);

    require watchedSigner == contextSigner;
    require watchedPrefix == getAddressPrefix(contextSigner);
    require !signerCalled && !signatureAccepted;

    call(e, permitCaller, account, 0, data);

    satisfy signatureAccepted && accountSeenBySigner == account;
}
