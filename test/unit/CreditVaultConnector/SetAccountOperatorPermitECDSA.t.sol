// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "src/test/CreditVaultConnectorScribble.sol";
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

contract Signer is EIP712, Test {
    CreditVaultConnector private immutable cvc;

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

    function signPermit(
        address account,
        address operator,
        uint40 authExpiryTimestamp,
        uint40 deadline,
        uint256 privateKey
    ) external view returns (bytes memory signature) {
        (, uint40 magicNumber) = cvc.getAccountOperator(account, operator);
        bytes32 structHash = keccak256(
            abi.encode(
                cvc.OPERATOR_PERMIT_TYPEHASH(),
                account,
                operator,
                authExpiryTimestamp,
                magicNumber,
                deadline
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            privateKey,
            _hashTypedDataV4(structHash)
        );
        signature = abi.encodePacked(r, s, v);
    }
}

contract SetAccountOperatorPermitECDSATest is Test {
    CreditVaultConnector internal cvc;
    Signer internal signer;

    event AccountOperatorAuthorized(
        address indexed account,
        address indexed operator,
        uint authExpiryTimestamp
    );
    event AccountsOwnerRegistered(
        uint152 indexed prefix,
        address indexed owner
    );

    function setUp() public {
        cvc = new CreditVaultConnectorScribble();
        signer = new Signer(cvc);
    }

    function test_SetAccountOperatorPermitECDSA(
        uint privateKey,
        address operator,
        uint40 authExpiry,
        uint40 seed
    ) public {
        vm.assume(
            privateKey > 0 &&
                privateKey <
                115792089237316195423570985008687907852837564279074904382605163141518161494337
        );
        address alice = vm.addr(privateKey);

        vm.assume(!cvc.haveCommonOwner(alice, operator));
        vm.assume(authExpiry >= seed && authExpiry < type(uint40).max - 1);
        vm.assume(seed > 0 && seed < type(uint40).max - 10);

        vm.warp(seed);

        for (uint i = 0; i < 256; ++i) {
            address account = address(uint160(uint160(alice) ^ i));

            {
                (uint40 expiryTimestamp, uint40 magicNumber) = cvc
                    .getAccountOperator(account, operator);
                assertEq(expiryTimestamp, 0);
                assertEq(magicNumber, 0);
            }

            if (i == 0) {
                vm.expectRevert(
                    CreditVaultConnector.CVC_AccountOwnerNotRegistered.selector
                );
                cvc.getAccountOwner(account);
            } else {
                assertEq(cvc.getAccountOwner(account), alice);
            }

            // sign permit
            bytes memory signature = signer.signPermit(
                account,
                operator,
                authExpiry,
                uint40(block.timestamp),
                privateKey
            );

            // authorize the operator
            if (i == 0) {
                vm.expectEmit(true, true, false, false, address(cvc));
                emit AccountsOwnerRegistered(
                    uint152(uint160(alice) >> 8),
                    alice
                );
            }
            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(account, operator, authExpiry);
            vm.recordLogs();
            cvc.setAccountOperatorPermitECDSA(
                account,
                operator,
                authExpiry,
                uint40(block.timestamp),
                signature
            );
            Vm.Log[] memory logs = vm.getRecordedLogs();

            {
                assertTrue(i == 0 ? logs.length == 2 : logs.length == 1); // AccountsOwnerRegistered event is emitted only once
                (uint40 expiryTimestamp, uint40 magicNumber) = cvc
                    .getAccountOperator(account, operator);
                assertEq(expiryTimestamp, authExpiry);
                assertEq(magicNumber, block.timestamp);
                assertEq(cvc.getAccountOwner(account), alice);
            }

            // it's not possible to carry out a reply attack
            vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
            cvc.setAccountOperatorPermitECDSA(
                account,
                operator,
                authExpiry,
                uint40(block.timestamp),
                signature
            );

            // early return if the operator is already enabled with the same expiry timestamp
            vm.warp(block.timestamp + 1);
            signature = signer.signPermit(
                account,
                operator,
                authExpiry,
                uint40(block.timestamp + 1),
                privateKey
            );

            vm.recordLogs();
            cvc.setAccountOperatorPermitECDSA(
                account,
                operator,
                authExpiry,
                uint40(block.timestamp + 1),
                signature
            );
            logs = vm.getRecordedLogs();

            {
                assertEq(logs.length, 0);
                (uint40 expiryTimestamp, uint40 magicNumber) = cvc
                    .getAccountOperator(account, operator);
                assertEq(expiryTimestamp, authExpiry);
                assertEq(magicNumber, block.timestamp);
                assertEq(cvc.getAccountOwner(account), alice);
            }

            // change the authorization expiry timestamp
            vm.warp(block.timestamp + 1);
            signature = signer.signPermit(
                account,
                operator,
                authExpiry + 1,
                uint40(block.timestamp),
                privateKey
            );

            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(account, operator, authExpiry + 1);
            vm.recordLogs();
            cvc.setAccountOperatorPermitECDSA(
                account,
                operator,
                authExpiry + 1,
                uint40(block.timestamp),
                signature
            );
            logs = vm.getRecordedLogs();

            {
                assertEq(logs.length, 1);
                (uint40 expiryTimestamp, uint40 magicNumber) = cvc
                    .getAccountOperator(account, operator);
                assertEq(expiryTimestamp, authExpiry + 1);
                assertEq(magicNumber, block.timestamp);
                assertEq(cvc.getAccountOwner(account), alice);
            }

            // deauthorize the operator
            vm.warp(block.timestamp + 1);
            signature = signer.signPermit(
                account,
                operator,
                1,
                uint40(block.timestamp),
                privateKey
            );

            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(account, operator, 1);
            vm.recordLogs();
            cvc.setAccountOperatorPermitECDSA(
                account,
                operator,
                1,
                uint40(block.timestamp),
                signature
            );
            logs = vm.getRecordedLogs();

            {
                assertEq(logs.length, 1);
                (uint40 expiryTimestamp, uint40 magicNumber) = cvc
                    .getAccountOperator(account, operator);
                assertEq(expiryTimestamp, 1);
                assertEq(magicNumber, block.timestamp);
                assertEq(cvc.getAccountOwner(account), alice);
            }

            // early return if the operator is already deauthorized with the same timestamp
            vm.warp(block.timestamp + 1);
            signature = signer.signPermit(
                account,
                operator,
                1,
                uint40(block.timestamp),
                privateKey
            );

            vm.recordLogs();
            cvc.setAccountOperatorPermitECDSA(
                account,
                operator,
                1,
                uint40(block.timestamp),
                signature
            );
            logs = vm.getRecordedLogs();

            {
                assertEq(logs.length, 0);
                (uint40 expiryTimestamp, uint40 magicNumber) = cvc
                    .getAccountOperator(account, operator);
                assertEq(expiryTimestamp, 1);
                assertEq(magicNumber, block.timestamp);
                assertEq(cvc.getAccountOwner(account), alice);
            }

            // set expiry timestamp to current block if special value is used
            vm.warp(block.timestamp + 1);
            signature = signer.signPermit(
                account,
                operator,
                type(uint40).max,
                uint40(block.timestamp),
                privateKey
            );

            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(account, operator, block.timestamp);
            vm.recordLogs();
            cvc.setAccountOperatorPermitECDSA(
                account,
                operator,
                type(uint40).max,
                uint40(block.timestamp),
                signature
            );
            logs = vm.getRecordedLogs();

            {
                assertTrue(logs.length == 1);
                (uint40 expiryTimestamp, uint40 magicNumber) = cvc
                    .getAccountOperator(account, operator);
                assertEq(expiryTimestamp, block.timestamp);
                assertEq(magicNumber, block.timestamp);
                assertEq(cvc.getAccountOwner(account), alice);
            }
        }
    }

    function test_RevertIfSignerNotAuthorized_SetAccountOperatorPermitECDSA(
        uint privateKey,
        address operator
    ) public {
        vm.assume(
            privateKey > 0 &&
                privateKey <
                115792089237316195423570985008687907852837564279074904382605163141518161494337
        );
        address alice = vm.addr(privateKey);
        vm.assume(!cvc.haveCommonOwner(alice, operator));

        address account = address(uint160(uint160(alice) ^ 256));
        bytes memory signature = signer.signPermit(
            account,
            operator,
            0,
            uint40(block.timestamp),
            privateKey
        );

        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperatorPermitECDSA(
            account,
            operator,
            0,
            uint40(block.timestamp),
            signature
        );

        // succeeds if signer is authorized
        account = address(uint160(uint160(alice) ^ 255));
        signature = signer.signPermit(
            account,
            operator,
            0,
            uint40(block.timestamp),
            privateKey
        );

        cvc.setAccountOperatorPermitECDSA(
            account,
            operator,
            0,
            uint40(block.timestamp),
            signature
        );

        // reverts if signer is not a registered owner
        vm.warp(block.timestamp + 1);
        signature = signer.signPermit(
            account,
            operator,
            0,
            uint40(block.timestamp),
            uint(keccak256(abi.encode(privateKey))) // not a registered owner
        );

        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperatorPermitECDSA(
            account,
            operator,
            0,
            uint40(block.timestamp),
            signature
        );
    }

    function test_RevertIfOperatorIsOwnersAccount_SetAccountOperatorPermitECDSA(
        uint privateKey,
        uint8 subAccountId
    ) public {
        vm.assume(
            privateKey > 0 &&
                privateKey <
                115792089237316195423570985008687907852837564279074904382605163141518161494337
        );
        address alice = vm.addr(privateKey);
        address operator = address(uint160(uint160(alice) ^ subAccountId));

        bytes memory signature = signer.signPermit(
            alice,
            operator,
            0,
            uint40(block.timestamp),
            privateKey
        );

        vm.expectRevert(CreditVaultConnector.CVC_InvalidAddress.selector);
        cvc.setAccountOperatorPermitECDSA(
            alice,
            operator,
            0,
            uint40(block.timestamp),
            signature
        );
    }

    function test_RevertIfPermitDeadlineMissed_SetAccountOperatorPermitECDSA(
        uint privateKey,
        address operator,
        uint40 seed
    ) public {
        vm.assume(
            privateKey > 0 &&
                privateKey <
                115792089237316195423570985008687907852837564279074904382605163141518161494337
        );
        address alice = vm.addr(privateKey);
        vm.assume(!cvc.haveCommonOwner(alice, operator));
        vm.assume(seed > 0);

        vm.warp(seed);

        bytes memory signature = signer.signPermit(
            alice,
            operator,
            0,
            uint40(block.timestamp - 1),
            privateKey
        );
        vm.expectRevert(CreditVaultConnector.CVC_InvalidTimestamp.selector);
        cvc.setAccountOperatorPermitECDSA(
            alice,
            operator,
            0,
            uint40(block.timestamp - 1),
            signature
        );

        // succeeds if deadline is not missed
        signature = signer.signPermit(
            alice,
            operator,
            0,
            uint40(block.timestamp),
            privateKey
        );
        cvc.setAccountOperatorPermitECDSA(
            alice,
            operator,
            0,
            uint40(block.timestamp),
            signature
        );
    }

    function test_RevertIfInvalidSignature_SetAccountOperatorPermitECDSA(
        uint privateKey,
        address operator,
        uint40 seed
    ) public {
        vm.assume(
            privateKey > 0 &&
                privateKey <
                115792089237316195423570985008687907852837564279074904382605163141518161494337
        );
        address alice = vm.addr(privateKey);
        vm.assume(uint160(operator) != type(uint160).max);
        vm.assume(!cvc.haveCommonOwner(alice, operator));
        vm.assume(seed > 0 && seed < type(uint40).max - 10);
        vm.warp(seed);

        bytes memory signature = signer.signPermit(
            address(uint160(alice) + 1),
            operator,
            0,
            uint40(block.timestamp),
            privateKey
        );
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperatorPermitECDSA(
            alice,
            operator,
            0,
            uint40(block.timestamp),
            signature
        );

        signature = signer.signPermit(
            alice,
            address(uint160(operator) + 1),
            0,
            uint40(block.timestamp),
            privateKey
        );
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperatorPermitECDSA(
            alice,
            operator,
            0,
            uint40(block.timestamp),
            signature
        );

        signature = signer.signPermit(
            alice,
            operator,
            1,
            uint40(block.timestamp),
            privateKey
        );
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperatorPermitECDSA(
            alice,
            operator,
            0,
            uint40(block.timestamp),
            signature
        );

        signature = signer.signPermit(
            alice,
            operator,
            0,
            uint40(block.timestamp + 1),
            privateKey
        );
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperatorPermitECDSA(
            alice,
            operator,
            0,
            uint40(block.timestamp),
            signature
        );

        // succeeds if signature is valid
        signature = signer.signPermit(
            alice,
            operator,
            0,
            uint40(block.timestamp),
            privateKey
        );
        cvc.setAccountOperatorPermitECDSA(
            alice,
            operator,
            0,
            uint40(block.timestamp),
            signature
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
        vm.expectRevert(CreditVaultConnector.CVC_InvalidSignature.selector);
        cvc.setAccountOperatorPermitECDSA(
            alice,
            operator,
            0,
            uint40(block.timestamp),
            signature
        );

        signature = abi.encodePacked(uint(0), s, v);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidSignature.selector);
        cvc.setAccountOperatorPermitECDSA(
            alice,
            operator,
            0,
            uint40(block.timestamp),
            signature
        );

        signature = abi.encodePacked(r, uint(0), v);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidSignature.selector);
        cvc.setAccountOperatorPermitECDSA(
            alice,
            operator,
            0,
            uint40(block.timestamp),
            signature
        );

        signature = abi.encodePacked(r, s, uint8(0));
        vm.expectRevert(CreditVaultConnector.CVC_InvalidSignature.selector);
        cvc.setAccountOperatorPermitECDSA(
            alice,
            operator,
            0,
            uint40(block.timestamp),
            signature
        );

        signature = abi.encodePacked(
            r,
            uint(
                0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1
            ),
            v
        );
        vm.expectRevert(CreditVaultConnector.CVC_InvalidSignature.selector);
        cvc.setAccountOperatorPermitECDSA(
            alice,
            operator,
            0,
            uint40(block.timestamp),
            signature
        );
    }

    function test_RevertIfPermitInvalidated_SetAccountOperatorPermitECDSA(
        uint privateKey,
        address operator,
        uint40 seed
    ) public {
        vm.assume(
            privateKey > 0 &&
                privateKey <
                115792089237316195423570985008687907852837564279074904382605163141518161494337
        );
        address alice = vm.addr(privateKey);
        vm.assume(uint160(operator) != type(uint160).max);
        vm.assume(!cvc.haveCommonOwner(alice, operator));
        vm.assume(seed > 0 && seed < type(uint40).max - 10);

        vm.warp(seed);
        bytes memory signature1 = signer.signPermit(
            alice,
            operator,
            0,
            uint40(block.timestamp),
            privateKey
        );
        bytes memory signature2 = signer.signPermit(
            alice,
            address(uint160(operator) + 1),
            0,
            uint40(block.timestamp),
            privateKey
        );

        vm.prank(alice);
        cvc.invalidateAllPermits();

        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperatorPermitECDSA(
            alice,
            operator,
            0,
            uint40(block.timestamp),
            signature1
        );
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperatorPermitECDSA(
            alice,
            address(uint160(operator) + 1),
            0,
            uint40(block.timestamp),
            signature2
        );

        vm.warp(block.timestamp + 1);
        signature1 = signer.signPermit(
            alice,
            operator,
            0,
            uint40(block.timestamp),
            privateKey
        );
        signature2 = signer.signPermit(
            alice,
            address(uint160(operator) + 1),
            0,
            uint40(block.timestamp),
            privateKey
        );

        vm.prank(alice);
        cvc.invalidateAccountOperatorPermits(alice, operator);

        // only one permit is invalid
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperatorPermitECDSA(
            alice,
            operator,
            0,
            uint40(block.timestamp),
            signature1
        );
        cvc.setAccountOperatorPermitECDSA(
            alice,
            address(uint160(operator) + 1),
            0,
            uint40(block.timestamp),
            signature2
        );

        // succeeds if permit is not invalidated
        vm.warp(block.timestamp + 1);
        signature1 = signer.signPermit(
            alice,
            operator,
            0,
            uint40(block.timestamp),
            privateKey
        );
        cvc.setAccountOperatorPermitECDSA(
            alice,
            operator,
            0,
            uint40(block.timestamp),
            signature1
        );

        // reverts if replayed
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperatorPermitECDSA(
            alice,
            operator,
            0,
            uint40(block.timestamp),
            signature1
        );
    }
}
