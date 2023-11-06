// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../utils/mocks/Target.sol";
import "../../cvc/CreditVaultConnectorHarness.sol";
import "openzeppelin/utils/cryptography/ECDSA.sol";
import {ShortStrings, ShortString} from "openzeppelin/utils/ShortStrings.sol";

abstract contract EIP712 {
    using ShortStrings for *;

    bytes32 internal constant _TYPE_HASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    bytes32 internal immutable _hashedName;
    bytes32 internal immutable _hashedVersion;

    ShortString private immutable _name;
    ShortString private immutable _version;
    string private _nameFallback;
    string private _versionFallback;

    /**
     * @dev Initializes the domain separator.
     *
     * The meaning of `name` and `version` is specified in
     * https://eips.ethereum.org/EIPS/eip-712#definition-of-domainseparator[EIP 712]:
     *
     * - `name`: the user readable name of the signing domain, i.e. the name of the DApp or the protocol.
     * - `version`: the current major version of the signing domain.
     *
     * NOTE: These parameters cannot be changed except through a xref:learn::upgrading-smart-contracts.adoc[smart
     * contract upgrade].
     */
    constructor(string memory name, string memory version) {
        _name = name.toShortStringWithFallback(_nameFallback);
        _version = version.toShortStringWithFallback(_versionFallback);
        _hashedName = keccak256(bytes(name));
        _hashedVersion = keccak256(bytes(version));
    }

    /**
     * @dev Returns the domain separator for the current chain.
     */
    function _domainSeparatorV4() internal view returns (bytes32) {
        return _buildDomainSeparator();
    }

    function _buildDomainSeparator() internal view virtual returns (bytes32) {
        return bytes32(0);
    }

    /**
     * @dev Given an already https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct[hashed struct], this
     * function returns the hash of the fully encoded EIP712 message for this domain.
     *
     * This hash can be used together with {ECDSA-recover} to obtain the signer of a message. For example:
     *
     * ```solidity
     * bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
     *     keccak256("Mail(address to,string contents)"),
     *     mailTo,
     *     keccak256(bytes(mailContents))
     * )));
     * address signer = ECDSA.recover(digest, signature);
     * ```
     */
    function _hashTypedDataV4(
        bytes32 structHash
    ) internal view virtual returns (bytes32) {
        return ECDSA.toTypedDataHash(_domainSeparatorV4(), structHash);
    }
}

contract SignerECDSA is EIP712, Test {
    CreditVaultConnector private immutable cvc;
    uint256 private privateKey;

    constructor(CreditVaultConnector _cvc) EIP712(_cvc.name(), _cvc.version()) {
        cvc = _cvc;
    }

    function setPrivateKey(uint256 _privateKey) external {
        privateKey = _privateKey;
    }

    function _buildDomainSeparator() internal view override returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    _TYPE_HASH,
                    _hashedName,
                    _hashedVersion,
                    block.chainid,
                    address(cvc)
                )
            );
    }

    function signPermit(
        address signer,
        uint nonceNamespace,
        uint nonce,
        uint deadline,
        uint value,
        bytes calldata data
    ) external view returns (bytes memory signature) {
        bytes32 structHash = keccak256(
            abi.encode(
                cvc.PERMIT_TYPEHASH(),
                signer,
                nonceNamespace,
                nonce,
                deadline,
                value,
                keccak256(data)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            privateKey,
            _hashTypedDataV4(structHash)
        );
        signature = abi.encodePacked(r, s, v);
    }
}

contract SignerERC1271 is EIP712, IERC1271 {
    CreditVaultConnector private immutable cvc;
    bytes32 private signatureHash;
    bytes32 private permitHash;

    constructor(CreditVaultConnector _cvc) EIP712(_cvc.name(), _cvc.version()) {
        cvc = _cvc;
    }

    function _buildDomainSeparator() internal view override returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    _TYPE_HASH,
                    _hashedName,
                    _hashedVersion,
                    block.chainid,
                    address(cvc)
                )
            );
    }

    function setSignatureHash(bytes calldata signature) external {
        signatureHash = keccak256(signature);
    }

    function setPermitHash(
        address signer,
        uint nonceNamespace,
        uint nonce,
        uint deadline,
        uint value,
        bytes calldata data
    ) external {
        bytes32 structHash = keccak256(
            abi.encode(
                cvc.PERMIT_TYPEHASH(),
                signer,
                nonceNamespace,
                nonce,
                deadline,
                value,
                keccak256(data)
            )
        );
        permitHash = _hashTypedDataV4(structHash);
    }

    function isValidSignature(
        bytes32 hash,
        bytes memory signature
    ) external view returns (bytes4 magicValue) {
        if (hash == permitHash && signatureHash == keccak256(signature)) {
            magicValue = this.isValidSignature.selector;
        }
    }
}

contract CreditVaultConnectorWithFallback is CreditVaultConnectorHarness {
    bytes32 internal expectedHash;
    uint internal expectedValue;
    bool internal shouldRevert;
    bool public fallbackCalled;

    function setExpectedHash(bytes calldata data) external {
        expectedHash = keccak256(data);
    }

    function setExpectedValue(uint value) external {
        expectedValue = value;
    }

    function setShouldRevert(bool sr) external {
        shouldRevert = sr;
    }

    function clearFallbackCalled() external {
        fallbackCalled = false;
    }

    fallback(bytes calldata data) external payable returns (bytes memory) {
        if (shouldRevert) revert("fallback reverted");

        if (
            expectedHash == keccak256(data) &&
            expectedValue == msg.value &&
            address(this) == msg.sender
        ) {
            fallbackCalled = true;
        }

        return data;
    }
}

contract PermitTest is Test {
    CreditVaultConnectorWithFallback internal cvc;
    SignerECDSA internal signerECDSA;
    SignerERC1271 internal signerERC1271;

    event NonceUsed(uint152 indexed addressPrefix, uint nonce);
    event CallWithContext(
        address indexed caller,
        address indexed targetContract,
        address indexed onBehalfOfAccount,
        bytes4 selector
    );

    function setUp() public {
        cvc = new CreditVaultConnectorWithFallback();
        signerECDSA = new SignerECDSA(cvc);
    }

    function test_ECDSA_Permit(
        uint privateKey,
        uint nonceNamespace,
        uint nonce,
        uint deadline,
        bytes memory data,
        uint16 value
    ) public {
        vm.assume(
            privateKey > 0 &&
                privateKey <
                115792089237316195423570985008687907852837564279074904382605163141518161494337
        );
        address alice = vm.addr(privateKey);
        uint152 addressPrefix = cvc.getAddressPrefix(alice);
        data = abi.encode(keccak256(data));

        vm.assume(
            !cvc.haveCommonOwner(alice, address(0)) && alice != address(cvc)
        );
        vm.assume(nonce > 0 && nonce < type(uint).max);

        vm.warp(deadline);
        vm.deal(address(this), type(uint128).max);
        signerECDSA.setPrivateKey(privateKey);

        if (nonce > 1) {
            vm.prank(alice);
            cvc.setNonce(addressPrefix, nonceNamespace, nonce - 1);
        }

        cvc.clearFallbackCalled();
        cvc.setExpectedHash(data);
        cvc.setExpectedValue(value);

        bytes memory signature = signerECDSA.signPermit(
            alice,
            nonceNamespace,
            nonce,
            deadline,
            value,
            data
        );

        vm.expectEmit(true, false, false, true, address(cvc));
        emit NonceUsed(cvc.getAddressPrefix(alice), nonce);
        vm.expectEmit(true, true, true, true, address(cvc));
        emit CallWithContext(address(this), address(cvc), alice, bytes4(data));
        cvc.permit{value: address(this).balance}(
            alice,
            nonceNamespace,
            nonce,
            deadline,
            value,
            data,
            signature
        );
        assertTrue(cvc.fallbackCalled());

        // it's not possible to carry out a reply attack
        vm.expectRevert(Errors.CVC_InvalidNonce.selector);
        cvc.permit{value: address(this).balance}(
            alice,
            nonceNamespace,
            nonce,
            deadline,
            value,
            data,
            signature
        );
    }

    function test_ERC1271_Permit(
        uint nonceNamespace,
        uint nonce,
        uint deadline,
        bytes memory data,
        bytes calldata signature,
        uint16 value
    ) public {
        address alice = address(new SignerERC1271(cvc));
        uint152 addressPrefix = cvc.getAddressPrefix(alice);
        data = abi.encode(keccak256(data));

        vm.assume(!cvc.haveCommonOwner(alice, address(0)));
        vm.assume(nonce > 0 && nonce < type(uint).max);

        vm.warp(deadline);
        vm.deal(address(this), type(uint128).max);
        SignerERC1271(alice).setSignatureHash(signature);

        if (nonce > 1) {
            vm.prank(alice);
            cvc.setNonce(addressPrefix, nonceNamespace, nonce - 1);
        }

        cvc.clearFallbackCalled();
        cvc.setExpectedHash(data);
        cvc.setExpectedValue(value);

        SignerERC1271(alice).setPermitHash(
            alice,
            nonceNamespace,
            nonce,
            deadline,
            value,
            data
        );

        vm.expectEmit(true, false, false, true, address(cvc));
        emit NonceUsed(cvc.getAddressPrefix(alice), nonce);
        vm.expectEmit(true, true, true, true, address(cvc));
        emit CallWithContext(address(this), address(cvc), alice, bytes4(data));
        cvc.permit{value: address(this).balance}(
            alice,
            nonceNamespace,
            nonce,
            deadline,
            value,
            data,
            signature
        );
        assertTrue(cvc.fallbackCalled());

        // it's not possible to carry out a reply attack
        vm.expectRevert(Errors.CVC_InvalidNonce.selector);
        cvc.permit{value: address(this).balance}(
            alice,
            nonceNamespace,
            nonce,
            deadline,
            value,
            data,
            signature
        );
    }

    function test_RevertIfSignerInvalid_Permit(
        address alice,
        uint nonceNamespace,
        uint nonce,
        uint deadline,
        uint value,
        bytes memory data,
        bytes calldata signature
    ) public {
        alice = address(uint160(bound(uint160(alice), 0, 0xFF)));
        uint152 addressPrefix = cvc.getAddressPrefix(alice);
        data = abi.encode(keccak256(data));
        vm.assume(nonce > 0 && nonce < type(uint).max);
        vm.warp(deadline);

        if (nonce > 1) {
            vm.prank(alice);
            cvc.setNonce(addressPrefix, nonceNamespace, nonce - 1);
        }

        // reverts if signer is zero address
        vm.expectRevert(Errors.CVC_InvalidAddress.selector);
        cvc.permit(
            alice,
            nonceNamespace,
            nonce,
            deadline,
            value,
            data,
            signature
        );
    }

    function test_RevertIfNonceInvalid_Permit(
        address alice,
        uint nonceNamespace,
        uint nonce,
        uint deadline,
        uint value,
        bytes memory data,
        bytes calldata signature
    ) public {
        uint152 addressPrefix = cvc.getAddressPrefix(alice);
        data = abi.encode(keccak256(data));
        vm.assume(
            !cvc.haveCommonOwner(alice, address(0)) && alice != address(cvc)
        );
        vm.assume(nonce > 0);
        vm.warp(deadline);

        vm.prank(alice);
        cvc.setNonce(addressPrefix, nonceNamespace, nonce);

        // reverts if nonce is invalid
        vm.expectRevert(Errors.CVC_InvalidNonce.selector);
        cvc.permit(
            alice,
            nonceNamespace,
            nonce,
            deadline,
            value,
            data,
            signature
        );
    }

    function test_RevertIfDeadlineMissed_Permit(
        address alice,
        uint nonceNamespace,
        uint nonce,
        uint deadline,
        uint value,
        bytes memory data,
        bytes calldata signature
    ) public {
        uint152 addressPrefix = cvc.getAddressPrefix(alice);
        data = abi.encode(keccak256(data));
        vm.assume(
            !cvc.haveCommonOwner(alice, address(0)) && alice != address(cvc)
        );
        vm.assume(nonce > 0 && nonce < type(uint).max);
        vm.assume(deadline < type(uint).max);
        vm.warp(deadline + 1);

        if (nonce > 1) {
            vm.prank(alice);
            cvc.setNonce(addressPrefix, nonceNamespace, nonce - 1);
        }

        // reverts if deadline is missed
        vm.expectRevert(Errors.CVC_InvalidTimestamp.selector);
        cvc.permit(
            alice,
            nonceNamespace,
            nonce,
            deadline,
            value,
            data,
            signature
        );
    }

    function test_RevertIfValueExceedsBalance_Permit(
        uint privateKey,
        uint nonceNamespace,
        uint nonce,
        uint deadline,
        uint128 value,
        bytes memory data
    ) public {
        vm.assume(
            privateKey > 0 &&
                privateKey <
                115792089237316195423570985008687907852837564279074904382605163141518161494337
        );
        address alice = vm.addr(privateKey);
        uint152 addressPrefix = cvc.getAddressPrefix(alice);
        data = abi.encode(keccak256(data));
        vm.assume(
            !cvc.haveCommonOwner(alice, address(0)) && alice != address(cvc)
        );
        vm.assume(nonce > 0 && nonce < type(uint).max);
        vm.assume(value > 0);
        vm.warp(deadline);

        signerECDSA.setPrivateKey(privateKey);
        bytes memory signature = signerECDSA.signPermit(
            alice,
            nonceNamespace,
            nonce,
            deadline,
            value,
            data
        );

        if (nonce > 1) {
            vm.prank(alice);
            cvc.setNonce(addressPrefix, nonceNamespace, nonce - 1);
        }

        // reverts if value exceeds balance
        vm.deal(address(cvc), value - 1);
        vm.expectRevert(Errors.CVC_InvalidValue.selector);
        cvc.permit(
            alice,
            nonceNamespace,
            nonce,
            deadline,
            value,
            data,
            signature
        );

        // succeeds if value does not exceed balance
        vm.deal(address(cvc), value);
        cvc.permit(
            alice,
            nonceNamespace,
            nonce,
            deadline,
            value,
            data,
            signature
        );
    }

    function test_RevertIfDataIsInvalid_Permit(
        address alice,
        uint nonceNamespace,
        uint nonce,
        uint deadline,
        uint value,
        bytes calldata signature
    ) public {
        uint152 addressPrefix = cvc.getAddressPrefix(alice);
        vm.assume(
            !cvc.haveCommonOwner(alice, address(0)) && alice != address(cvc)
        );
        vm.assume(nonce > 0 && nonce < type(uint).max);
        vm.warp(deadline);

        if (nonce > 1) {
            vm.prank(alice);
            cvc.setNonce(addressPrefix, nonceNamespace, nonce - 1);
        }

        // reverts if data is empty
        vm.expectRevert(Errors.CVC_InvalidData.selector);
        cvc.permit(
            alice,
            nonceNamespace,
            nonce,
            deadline,
            value,
            bytes(""),
            signature
        );
    }

    function test_RevertIfCallUnsuccessful_Permit(
        uint privateKey,
        uint nonceNamespace,
        uint nonce,
        uint deadline,
        uint128 value,
        bytes memory data
    ) public {
        vm.chainId(5); // for coverage
        vm.assume(
            privateKey > 0 &&
                privateKey <
                115792089237316195423570985008687907852837564279074904382605163141518161494337
        );
        address alice = vm.addr(privateKey);
        uint152 addressPrefix = cvc.getAddressPrefix(alice);
        data = abi.encode(keccak256(data));
        signerECDSA.setPrivateKey(privateKey);

        vm.assume(
            !cvc.haveCommonOwner(alice, address(0)) && alice != address(cvc)
        );
        vm.assume(nonce > 0 && nonce < type(uint).max);
        vm.warp(deadline);
        vm.deal(address(cvc), value);

        cvc.clearFallbackCalled();
        cvc.setExpectedHash(data);
        cvc.setExpectedValue(value);
        cvc.setShouldRevert(true);

        if (nonce > 1) {
            vm.prank(alice);
            cvc.setNonce(addressPrefix, nonceNamespace, nonce - 1);
        }

        // reverts if CVC self-call unsuccessful
        bytes memory signature = signerECDSA.signPermit(
            alice,
            nonceNamespace,
            nonce,
            deadline,
            value,
            data
        );

        vm.expectRevert(bytes("fallback reverted"));
        cvc.permit(
            alice,
            nonceNamespace,
            nonce,
            deadline,
            value,
            data,
            signature
        );

        // succeeds if CVC self-call successful
        cvc.setShouldRevert(false);

        cvc.permit(
            alice,
            nonceNamespace,
            nonce,
            deadline,
            value,
            data,
            signature
        );
        assertTrue(cvc.fallbackCalled());
    }

    function test_RevertIfInvalidECDSASignature_Permit(
        uint privateKey,
        uint128 deadline
    ) public {
        vm.assume(
            privateKey > 0 &&
                privateKey <
                115792089237316195423570985008687907852837564279074904382605163141518161494337
        );
        address alice = vm.addr(privateKey);
        signerECDSA.setPrivateKey(privateKey);

        vm.assume(!cvc.haveCommonOwner(alice, address(0)));
        vm.warp(deadline);

        // ECDSA signature invalid due to signer.
        // ERC-1271 signature invalid as the signer is EOA and isValidSignature() call is unsuccesful
        bytes memory signature = signerECDSA.signPermit(
            address(uint160(alice) + 1),
            0,
            1,
            deadline,
            0,
            bytes("0")
        );
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit(alice, 0, 1, deadline, 0, bytes("0"), signature);

        // ECDSA signature invalid due to nonce namespace.
        // ERC-1271 signature invalid as the signer is EOA and isValidSignature() call is unsuccesful
        signature = signerECDSA.signPermit(
            alice,
            1,
            1,
            deadline,
            0,
            bytes("0")
        );
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit(alice, 0, 1, deadline, 0, bytes("0"), signature);

        // ECDSA signature invalid due to nonce.
        // ERC-1271 signature invalid as the signer is EOA and isValidSignature() call is unsuccesful
        signature = signerECDSA.signPermit(
            alice,
            0,
            2,
            deadline,
            0,
            bytes("0")
        );
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit(alice, 0, 1, deadline, 0, bytes("0"), signature);

        // ECDSA signature invalid due to deadline.
        // ERC-1271 signature invalid as the signer is EOA and isValidSignature() call is unsuccesful
        signature = signerECDSA.signPermit(
            alice,
            0,
            1,
            uint(deadline) + 1,
            0,
            bytes("0")
        );
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit(alice, 0, 1, deadline, 0, bytes("0"), signature);

        // ECDSA signature invalid due to value.
        // ERC-1271 signature invalid as the signer is EOA and isValidSignature() call is unsuccesful
        signature = signerECDSA.signPermit(
            alice,
            0,
            1,
            deadline,
            1,
            bytes("0")
        );
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit(alice, 0, 1, deadline, 0, bytes("0"), signature);

        // ECDSA signature invalid due to data.
        // ERC-1271 signature invalid as the signer is EOA and isValidSignature() call is unsuccesful
        signature = signerECDSA.signPermit(
            alice,
            0,
            1,
            deadline,
            0,
            bytes("1")
        );
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit(alice, 0, 1, deadline, 0, bytes("0"), signature);

        // ECDSA signature invalid (wrong length due to added 1).
        // ERC-1271 signature invalid as the signer is EOA and isValidSignature() call is unsuccesful
        signature = signerECDSA.signPermit(
            alice,
            0,
            1,
            deadline,
            0,
            bytes("0")
        );

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        signature = abi.encodePacked(r, s, v, uint8(1));
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit(alice, 0, 1, deadline, 0, bytes("0"), signature);

        // ECDSA signature invalid (r is 0).
        // ERC-1271 signature invalid as the signer is EOA and isValidSignature() call is unsuccesful
        signature = abi.encodePacked(uint(0), s, v);
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit(alice, 0, 1, deadline, 0, bytes("0"), signature);

        // ECDSA signature invalid (s is 0).
        // ERC-1271 signature invalid as the signer is EOA and isValidSignature() call is unsuccesful
        signature = abi.encodePacked(r, uint(0), v);
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit(alice, 0, 1, deadline, 0, bytes("0"), signature);

        // ECDSA signature invalid (v is 0).
        // ERC-1271 signature invalid as the signer is EOA and isValidSignature() call is unsuccesful
        signature = abi.encodePacked(r, s, uint8(0));
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit(alice, 0, 1, deadline, 0, bytes("0"), signature);

        // ECDSA signature invalid (malleability protection).
        // ERC-1271 signature invalid as the signer is EOA and isValidSignature() call is unsuccesful
        signature = abi.encodePacked(
            r,
            uint(
                0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1
            ),
            v
        );
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit(alice, 0, 1, deadline, 0, bytes("0"), signature);

        // ECDSA signature valid hence the transaction succeeds
        cvc.setExpectedHash(bytes("0"));
        signature = abi.encodePacked(r, s, v);
        cvc.permit(alice, 0, 1, deadline, 0, bytes("0"), signature);
        assertTrue(cvc.fallbackCalled());
    }

    function test_RevertIfInvalidERC1271Signature_Permit(
        uint128 deadline,
        bytes calldata signature
    ) public {
        address alice = address(new SignerERC1271(cvc));
        SignerERC1271(alice).setSignatureHash(signature);

        vm.assume(!cvc.haveCommonOwner(alice, address(0)));
        vm.warp(deadline);

        // ECDSA signature is always invalid here hence we fall back to ERC-1271 signature

        // ERC-1271 signature invalid due to the signer
        SignerERC1271(alice).setPermitHash(
            address(uint160(alice) + 1),
            0,
            1,
            deadline,
            0,
            bytes("0")
        );
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit(alice, 0, 1, deadline, 0, bytes("0"), signature);

        // ERC-1271 signature invalid due to the nonce namespace
        SignerERC1271(alice).setPermitHash(
            alice,
            1,
            1,
            deadline,
            0,
            bytes("0")
        );
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit(alice, 0, 1, deadline, 0, bytes("0"), signature);

        // ERC-1271 signature invalid due to the nonce
        SignerERC1271(alice).setPermitHash(
            alice,
            0,
            2,
            deadline,
            0,
            bytes("0")
        );
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit(alice, 0, 1, deadline, 0, bytes("0"), signature);

        // ERC-1271 signature invalid due to the deadline
        SignerERC1271(alice).setPermitHash(
            alice,
            0,
            1,
            uint(deadline) + 1,
            0,
            bytes("0")
        );
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit(alice, 0, 1, deadline, 0, bytes("0"), signature);

        // ERC-1271 signature invalid due to the value
        SignerERC1271(alice).setPermitHash(
            alice,
            0,
            1,
            deadline,
            1,
            bytes("0")
        );
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit(alice, 0, 1, deadline, 0, bytes("0"), signature);

        // ERC-1271 signature invalid due to the data
        SignerERC1271(alice).setPermitHash(
            alice,
            0,
            1,
            deadline,
            0,
            bytes("1")
        );
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit(alice, 0, 1, deadline, 0, bytes("0"), signature);

        // ERC-1271 signature valid hence the transaction succeeds
        cvc.setExpectedHash(bytes("0"));
        SignerERC1271(alice).setPermitHash(
            alice,
            0,
            1,
            deadline,
            0,
            bytes("0")
        );
        cvc.permit(alice, 0, 1, deadline, 0, bytes("0"), signature);
        assertTrue(cvc.fallbackCalled());
    }

    function test_Permit(uint privateKey) public {
        vm.assume(
            privateKey > 0 &&
                privateKey <
                115792089237316195423570985008687907852837564279074904382605163141518161494337
        );
        address alice = vm.addr(privateKey);
        address bob = address(new SignerERC1271(cvc));
        address target = address(new Target());

        vm.assume(
            !cvc.haveCommonOwner(alice, address(0)) &&
                !cvc.haveCommonOwner(alice, bob)
        );
        vm.deal(address(this), type(uint128).max);
        signerECDSA.setPrivateKey(privateKey);

        // encode a call that doesn't need authentication to prove it can be signed by anyone
        bytes memory data = abi.encodeWithSelector(
            ICVC.requireAccountStatusCheck.selector,
            address(0)
        );

        // a call using ECDSA signature succeeds
        bytes memory signature = signerECDSA.signPermit(
            alice,
            0,
            1,
            block.timestamp,
            0,
            data
        );
        cvc.permit(alice, 0, 1, block.timestamp, 0, data, signature);

        // a call using ERC-1271 signature succeeds
        signature = bytes("bob's signature");
        SignerERC1271(bob).setSignatureHash(signature);
        SignerERC1271(bob).setPermitHash(bob, 0, 1, block.timestamp, 0, data);
        cvc.permit(bob, 0, 1, block.timestamp, 0, data, signature);

        // encode a call that doesn't need authentication wrapped in a batch
        ICVC.BatchItem[] memory items = new ICVC.BatchItem[](1);
        items[0].targetContract = address(cvc);
        items[0].onBehalfOfAccount = address(0);
        items[0].value = 0;
        items[0].data = data;
        data = abi.encodeWithSelector(ICVC.batch.selector, items);

        // a call using ECDSA signature succeeds
        signature = signerECDSA.signPermit(
            alice,
            0,
            2,
            block.timestamp,
            0,
            data
        );
        cvc.permit(alice, 0, 2, block.timestamp, 0, data, signature);

        // a call using ERC-1271 signature succeeds
        signature = bytes("bob's signature");
        SignerERC1271(bob).setSignatureHash(signature);
        SignerERC1271(bob).setPermitHash(bob, 0, 2, block.timestamp, 0, data);
        cvc.permit(bob, 0, 2, block.timestamp, 0, data, signature);

        // encode a call that needs authentication to prove it cannot be signed by anyone
        data = abi.encodeWithSelector(
            ICVC.enableCollateral.selector,
            bob,
            address(0)
        );

        // a call using ECDSA signature fails because alice signed on behalf of bob
        signature = signerECDSA.signPermit(
            alice,
            0,
            3,
            block.timestamp,
            0,
            data
        );
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit(alice, 0, 3, block.timestamp, 0, data, signature);

        // a call using ERC1271 signature fails because bob signed on behalf of alice
        data = abi.encodeWithSelector(
            ICVC.enableCollateral.selector,
            alice,
            address(0)
        );
        signature = bytes("bob's signature");
        SignerERC1271(bob).setSignatureHash(signature);
        SignerERC1271(bob).setPermitHash(bob, 0, 3, block.timestamp, 0, data);
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit(bob, 0, 3, block.timestamp, 0, data, signature);

        // encode a call that needs authentication wrapped in a batch
        data = abi.encodeWithSelector(
            ICVC.enableCollateral.selector,
            bob,
            address(0)
        );
        items[0].targetContract = address(cvc);
        items[0].onBehalfOfAccount = bob;
        items[0].value = 0;
        items[0].data = data;
        data = abi.encodeWithSelector(ICVC.batch.selector, items);

        // a call using ECDSA signature fails because alice signed on behalf of bob
        signature = signerECDSA.signPermit(
            alice,
            0,
            3,
            block.timestamp,
            0,
            data
        );
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit(alice, 0, 3, block.timestamp, 0, data, signature);

        // a call using ERC1271 signature fails because bob signed on behalf of alice
        data = abi.encodeWithSelector(
            ICVC.enableCollateral.selector,
            alice,
            address(0)
        );
        items[0].targetContract = address(cvc);
        items[0].onBehalfOfAccount = alice;
        items[0].value = 0;
        items[0].data = data;
        data = abi.encodeWithSelector(ICVC.batch.selector, items);

        signature = bytes("bob's signature");
        SignerERC1271(bob).setSignatureHash(signature);
        SignerERC1271(bob).setPermitHash(bob, 0, 3, block.timestamp, 0, data);
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit(bob, 0, 3, block.timestamp, 0, data, signature);

        // encode a call that needs authentication
        data = abi.encodeWithSelector(
            ICVC.enableCollateral.selector,
            alice,
            address(0)
        );

        // a call using ECDSA signature succeeds because alice signed on behalf of herself
        signature = signerECDSA.signPermit(
            alice,
            0,
            3,
            block.timestamp,
            0,
            data
        );
        cvc.permit(alice, 0, 3, block.timestamp, 0, data, signature);

        // a call using ERC1271 signature succeeds because bob signed on behalf of himself
        data = abi.encodeWithSelector(
            ICVC.enableCollateral.selector,
            bob,
            address(0)
        );

        signature = bytes("bob's signature");
        SignerERC1271(bob).setSignatureHash(signature);
        SignerERC1271(bob).setPermitHash(bob, 0, 3, block.timestamp, 0, data);
        cvc.permit(bob, 0, 3, block.timestamp, 0, data, signature);

        // encode a call that needs authentication wrapped in a batch
        data = abi.encodeWithSelector(
            ICVC.enableCollateral.selector,
            alice,
            address(0)
        );
        items[0].targetContract = address(cvc);
        items[0].onBehalfOfAccount = alice;
        items[0].value = 0;
        items[0].data = data;
        data = abi.encodeWithSelector(ICVC.batch.selector, items);

        // a call using ECDSA signature succeeds because alice signed on behalf of herself
        signature = signerECDSA.signPermit(
            alice,
            0,
            4,
            block.timestamp,
            0,
            data
        );
        cvc.permit(alice, 0, 4, block.timestamp, 0, data, signature);

        // a call using ERC1271 signature succeeds because bob signed on behalf of himself
        data = abi.encodeWithSelector(
            ICVC.enableCollateral.selector,
            bob,
            address(0)
        );
        items[0].targetContract = address(cvc);
        items[0].onBehalfOfAccount = bob;
        items[0].value = 0;
        items[0].data = data;
        data = abi.encodeWithSelector(ICVC.batch.selector, items);

        signature = bytes("bob's signature");
        SignerERC1271(bob).setSignatureHash(signature);
        SignerERC1271(bob).setPermitHash(bob, 0, 4, block.timestamp, 0, data);
        cvc.permit(bob, 0, 4, block.timestamp, 0, data, signature);

        // encode a call to an external target contract
        data = abi.encodeWithSelector(
            ICVC.call.selector,
            target,
            bob,
            123,
            abi.encodeWithSelector(
                Target.callTest.selector,
                address(cvc),
                address(cvc),
                123,
                bob,
                false
            )
        );

        // a call using ECDSA signature fails because alice signed on behalf of bob
        signature = signerECDSA.signPermit(
            alice,
            0,
            5,
            block.timestamp,
            type(uint).max,
            data
        );
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit{value: 123}(
            alice,
            0,
            5,
            block.timestamp,
            type(uint).max,
            data,
            signature
        );

        // a call using ERC1271 signature fails because bob signed on behalf of alice
        data = abi.encodeWithSelector(
            ICVC.call.selector,
            target,
            alice,
            123,
            abi.encodeWithSelector(
                Target.callTest.selector,
                address(cvc),
                address(cvc),
                123,
                alice,
                false
            )
        );

        signature = bytes("bob's signature");
        SignerERC1271(bob).setSignatureHash(signature);
        SignerERC1271(bob).setPermitHash(
            bob,
            0,
            5,
            block.timestamp,
            type(uint).max,
            data
        );
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit{value: 123}(
            bob,
            0,
            5,
            block.timestamp,
            type(uint).max,
            data,
            signature
        );

        // encode a call to an external target contract wrapped in a batch
        data = abi.encodeWithSelector(
            Target.callTest.selector,
            address(cvc),
            address(cvc),
            123,
            bob,
            false
        );
        items[0].targetContract = target;
        items[0].onBehalfOfAccount = bob;
        items[0].value = 123;
        items[0].data = data;
        data = abi.encodeWithSelector(ICVC.batch.selector, items);

        // a call using ECDSA signature fails because alice signed on behalf of bob
        signature = signerECDSA.signPermit(
            alice,
            0,
            5,
            block.timestamp,
            type(uint).max,
            data
        );
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit{value: 123}(
            alice,
            0,
            5,
            block.timestamp,
            type(uint).max,
            data,
            signature
        );

        // a call using ERC1271 signature fails because bob signed on behalf of alice
        data = abi.encodeWithSelector(
            Target.callTest.selector,
            address(cvc),
            address(cvc),
            123,
            alice,
            false
        );
        items[0].targetContract = target;
        items[0].onBehalfOfAccount = alice;
        items[0].value = 123;
        items[0].data = data;
        data = abi.encodeWithSelector(ICVC.batch.selector, items);

        signature = bytes("bob's signature");
        SignerERC1271(bob).setSignatureHash(signature);
        SignerERC1271(bob).setPermitHash(
            bob,
            0,
            5,
            block.timestamp,
            type(uint).max,
            data
        );
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit{value: 123}(
            bob,
            0,
            5,
            block.timestamp,
            type(uint).max,
            data,
            signature
        );

        // encode a call to an external target contract
        data = abi.encodeWithSelector(
            ICVC.call.selector,
            target,
            alice,
            123,
            abi.encodeWithSelector(
                Target.callTest.selector,
                address(cvc),
                address(cvc),
                123,
                alice,
                false
            )
        );

        // a call using ECDSA signature succeeds because alice signed on behalf of herself
        signature = signerECDSA.signPermit(
            alice,
            0,
            5,
            block.timestamp,
            type(uint).max,
            data
        );
        cvc.permit{value: 123}(
            alice,
            0,
            5,
            block.timestamp,
            type(uint).max,
            data,
            signature
        );

        // a call using ERC1271 signature succeeds because bob signed on behalf of himself
        data = abi.encodeWithSelector(
            ICVC.call.selector,
            target,
            bob,
            123,
            abi.encodeWithSelector(
                Target.callTest.selector,
                address(cvc),
                address(cvc),
                123,
                bob,
                false
            )
        );

        signature = bytes("bob's signature");
        SignerERC1271(bob).setSignatureHash(signature);
        SignerERC1271(bob).setPermitHash(
            bob,
            0,
            5,
            block.timestamp,
            type(uint).max,
            data
        );
        cvc.permit{value: 123}(
            bob,
            0,
            5,
            block.timestamp,
            type(uint).max,
            data,
            signature
        );

        // encode a call to an external target contract wrapped in a batch
        data = abi.encodeWithSelector(
            Target.callTest.selector,
            address(cvc),
            address(cvc),
            456,
            alice,
            false
        );
        items[0].targetContract = target;
        items[0].onBehalfOfAccount = alice;
        items[0].value = 456;
        items[0].data = data;
        data = abi.encodeWithSelector(ICVC.batch.selector, items);

        // a call using ECDSA signature succeeds because alice signed on behalf of herself
        signature = signerECDSA.signPermit(
            alice,
            0,
            6,
            block.timestamp,
            456,
            data
        );
        cvc.permit{value: 456}(
            alice,
            0,
            6,
            block.timestamp,
            456,
            data,
            signature
        );

        // a call using ERC1271 signature succeeds because bob signed on behalf of himself
        data = abi.encodeWithSelector(
            Target.callTest.selector,
            address(cvc),
            address(cvc),
            456,
            bob,
            false
        );
        items[0].targetContract = target;
        items[0].onBehalfOfAccount = bob;
        items[0].value = 456;
        items[0].data = data;
        data = abi.encodeWithSelector(ICVC.batch.selector, items);

        signature = bytes("bob's signature");
        SignerERC1271(bob).setSignatureHash(signature);
        SignerERC1271(bob).setPermitHash(bob, 0, 6, block.timestamp, 456, data);
        cvc.permit{value: 456}(
            bob,
            0,
            6,
            block.timestamp,
            456,
            data,
            signature
        );
    }

    function test_SetOperator_Permit(
        uint privateKey,
        uint8 subAccountId1,
        uint8 subAccountId2
    ) public {
        vm.assume(
            privateKey > 0 &&
                privateKey <
                115792089237316195423570985008687907852837564279074904382605163141518161494335
        );
        address alice = vm.addr(privateKey);
        address bob = address(new SignerERC1271(cvc));
        uint152 addressPrefixAlice = cvc.getAddressPrefix(alice);
        uint152 addressPrefixBob = cvc.getAddressPrefix(bob);
        address operator = vm.addr(privateKey + 1);
        address otherOperator = vm.addr(privateKey + 2);

        vm.assume(alice != address(0) && bob != address(0));
        vm.assume(operator != address(0) && operator != address(cvc));
        vm.assume(
            !cvc.haveCommonOwner(alice, operator) &&
                !cvc.haveCommonOwner(bob, operator)
        );
        vm.assume(
            subAccountId1 > 0 &&
                subAccountId2 > 0 &&
                subAccountId1 != subAccountId2
        );
        signerECDSA.setPrivateKey(privateKey);

        ICVC.BatchItem[] memory items = new ICVC.BatchItem[](3);

        // encode the setAccountOperator to prove that it's possible to set an operator
        // on behalf of the signer or their accounts
        items[0].targetContract = address(cvc);
        items[0].onBehalfOfAccount = address(0);
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(
            ICVC.setAccountOperator.selector,
            alice,
            operator,
            true
        );
        items[1].targetContract = address(cvc);
        items[1].onBehalfOfAccount = address(0);
        items[1].value = 0;
        items[1].data = abi.encodeWithSelector(
            ICVC.setAccountOperator.selector,
            address(uint160(alice) ^ subAccountId1),
            operator,
            true
        );
        items[2].targetContract = address(cvc);
        items[2].onBehalfOfAccount = address(0);
        items[2].value = 0;
        items[2].data = abi.encodeWithSelector(
            ICVC.setOperator.selector,
            addressPrefixAlice,
            operator,
            (1 << 0) | (1 << subAccountId1) | (1 << subAccountId2)
        );
        bytes memory data = abi.encodeWithSelector(ICVC.batch.selector, items);

        // a call using ECDSA signature succeeds
        bytes memory signature = signerECDSA.signPermit(
            alice,
            0,
            1,
            block.timestamp,
            0,
            data
        );
        cvc.permit(alice, 0, 1, block.timestamp, 0, data, signature);
        assertEq(cvc.isAccountOperatorAuthorized(alice, operator), true);
        assertEq(
            cvc.isAccountOperatorAuthorized(
                address(uint160(alice) ^ subAccountId1),
                operator
            ),
            true
        );
        assertEq(
            cvc.isAccountOperatorAuthorized(
                address(uint160(alice) ^ subAccountId2),
                operator
            ),
            true
        );
        assertEq(
            cvc.getOperator(addressPrefixAlice, operator),
            (1 << 0) | (1 << subAccountId1) | (1 << subAccountId2)
        );

        // a call using ERC-1271 signature succeeds
        items[0].data = abi.encodeWithSelector(
            ICVC.setAccountOperator.selector,
            bob,
            operator,
            true
        );
        items[1].data = abi.encodeWithSelector(
            ICVC.setAccountOperator.selector,
            address(uint160(bob) ^ subAccountId1),
            operator,
            true
        );
        items[2].data = abi.encodeWithSelector(
            ICVC.setOperator.selector,
            addressPrefixBob,
            operator,
            (1 << 0) | (1 << subAccountId1) | (1 << subAccountId2)
        );
        data = abi.encodeWithSelector(ICVC.batch.selector, items);

        signature = bytes("bob's signature");
        SignerERC1271(bob).setSignatureHash(signature);
        SignerERC1271(bob).setPermitHash(bob, 0, 1, block.timestamp, 0, data);
        cvc.permit(bob, 0, 1, block.timestamp, 0, data, signature);
        assertEq(cvc.isAccountOperatorAuthorized(bob, operator), true);
        assertEq(
            cvc.isAccountOperatorAuthorized(
                address(uint160(bob) ^ subAccountId1),
                operator
            ),
            true
        );
        assertEq(
            cvc.isAccountOperatorAuthorized(
                address(uint160(bob) ^ subAccountId2),
                operator
            ),
            true
        );
        assertEq(
            cvc.getOperator(addressPrefixBob, operator),
            (1 << 0) | (1 << subAccountId1) | (1 << subAccountId2)
        );

        // if the operator tries to authorize some other operator directly, it's not possible
        vm.prank(operator);
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.setOperator(addressPrefixAlice, operator, 0);

        vm.prank(operator);
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.setOperator(addressPrefixAlice, otherOperator, 0);

        vm.prank(operator);
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.setAccountOperator(alice, otherOperator, true);

        vm.prank(operator);
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.setOperator(addressPrefixBob, operator, 0);

        vm.prank(operator);
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.setOperator(addressPrefixBob, otherOperator, 0);

        vm.prank(operator);
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.setAccountOperator(bob, otherOperator, true);

        // but it succeeds if it's done using the signed data
        data = abi.encodeWithSelector(
            ICVC.setOperator.selector,
            addressPrefixAlice,
            otherOperator,
            3
        );

        signature = signerECDSA.signPermit(
            alice,
            0,
            2,
            block.timestamp,
            0,
            data
        );
        vm.prank(operator);
        cvc.permit(alice, 0, 2, block.timestamp, 0, data, signature);
        assertEq(
            cvc.isAccountOperatorAuthorized(
                address(uint160(alice) ^ 1),
                otherOperator
            ),
            true
        );

        data = abi.encodeWithSelector(
            ICVC.setAccountOperator.selector,
            alice,
            otherOperator,
            true
        );

        signature = signerECDSA.signPermit(
            alice,
            0,
            3,
            block.timestamp,
            0,
            data
        );
        vm.prank(operator);
        cvc.permit(alice, 0, 3, block.timestamp, 0, data, signature);
        assertEq(cvc.isAccountOperatorAuthorized(alice, otherOperator), true);

        data = abi.encodeWithSelector(
            ICVC.setOperator.selector,
            addressPrefixBob,
            otherOperator,
            3
        );

        signature = bytes("bob's signature");
        SignerERC1271(bob).setSignatureHash(signature);
        SignerERC1271(bob).setPermitHash(bob, 0, 2, block.timestamp, 0, data);

        vm.prank(operator);
        cvc.permit(bob, 0, 2, block.timestamp, 0, data, signature);
        assertEq(
            cvc.isAccountOperatorAuthorized(
                address(uint160(bob) ^ 1),
                otherOperator
            ),
            true
        );

        data = abi.encodeWithSelector(
            ICVC.setAccountOperator.selector,
            bob,
            otherOperator,
            true
        );
        signature = bytes("bob's signature");
        SignerERC1271(bob).setSignatureHash(signature);
        SignerERC1271(bob).setPermitHash(bob, 0, 3, block.timestamp, 0, data);

        vm.prank(operator);
        cvc.permit(bob, 0, 3, block.timestamp, 0, data, signature);
        assertEq(cvc.isAccountOperatorAuthorized(bob, otherOperator), true);

        // when the operator is authorized, it can sign permit messages on behalf of the authorized account
        signerECDSA.setPrivateKey(privateKey + 1);

        data = abi.encodeWithSelector(
            ICVC.enableCollateral.selector,
            alice,
            address(0)
        );

        signature = signerECDSA.signPermit(
            operator,
            0,
            1,
            block.timestamp,
            0,
            data
        );
        cvc.permit(operator, 0, 1, block.timestamp, 0, data, signature);
        assertEq(cvc.isCollateralEnabled(alice, address(0)), true);

        // and another one
        data = abi.encodeWithSelector(
            Target.callTest.selector,
            address(cvc),
            address(cvc),
            0,
            alice,
            true
        );

        signature = signerECDSA.signPermit(
            operator,
            0,
            2,
            block.timestamp,
            0,
            data
        );
        cvc.permit(operator, 0, 2, block.timestamp, 0, data, signature);

        // but it cannot sign permit messages on behalf of other accounts for which it's not authorized
        vm.prank(operator);
        cvc.setAccountOperator(
            address(uint160(alice) ^ subAccountId1),
            operator,
            false
        );

        data = abi.encodeWithSelector(
            ICVC.enableCollateral.selector,
            address(uint160(alice) ^ subAccountId1),
            address(0)
        );

        signature = signerECDSA.signPermit(
            operator,
            0,
            3,
            block.timestamp,
            0,
            data
        );
        vm.expectRevert(Errors.CVC_NotAuthorized.selector);
        cvc.permit(operator, 0, 3, block.timestamp, 0, data, signature);
    }
}
