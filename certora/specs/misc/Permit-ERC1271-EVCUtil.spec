// Since EVC v1.0.2, EVCUtil's authentication helpers revert when the EVC calls
// isValidSignature, so a signer that authenticates its caller through EVCUtil
// never approves a permit through ERC-1271, whatever the execution context
// holds. Without that check the rule fails: the signer approves as in
// Permit-ERC1271-signer-context.spec.

using EVCUtilSigner as evcUtilSigner;

methods {
    function getAddressPrefix(address) external returns (bytes19) envfree;
    function EVCUtilSigner.EVC() external returns (address) envfree;

    // Routes the EVC's low-level ERC-1271 staticcall to the signer.
    unresolved external in _._ => DISPATCH [
        EVCUtilSigner.isValidSignature(bytes32, bytes)
    ] default NONDET;

    // The signer here is a contract, for which no ECDSA key exists.
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

persistent ghost bytes19 watchedPrefix;
persistent ghost bool signatureAccepted;

// permit() consumes the signer's nonce only after accepting the signature.
hook Sstore EthereumVaultConnectorHarness.nonceLookup[KEY bytes19 prefix][KEY uint256 nonceNamespace] uint256 newNonce {
    if (prefix == watchedPrefix) {
        signatureAccepted = true;
    }
}

rule evcutil_signer_never_approves_erc1271_permit {
    env e;
    address sender;
    uint256 nonceNamespace;
    uint256 nonce;
    uint256 deadline;
    uint256 value;
    bytes data;
    bytes signature;

    require evcUtilSigner.EVC() == currentContract;
    require watchedPrefix == getAddressPrefix(evcUtilSigner);
    require !signatureAccepted;

    permit@withrevert(e, evcUtilSigner, sender, nonceNamespace, nonce, deadline, value, data, signature);

    assert !signatureAccepted;
}
