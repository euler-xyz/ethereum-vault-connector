// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "src/test/CreditVaultConnectorHarness.sol";
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

contract Signer is EIP712, IERC1271 {
    CreditVaultConnector private immutable cvc;
    mapping(bytes32 permit => bytes32 signatureHash) internal signatureLookup;

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

    function setSignature(
        address account,
        address operator,
        uint40 authExpiryTimestamp,
        uint40 signatureTimestamp,
        uint40 signatureDeadlineTimestamp,
        bytes memory signature
    ) external {
        bytes32 structHash = keccak256(
            abi.encode(
                cvc.OPERATOR_PERMIT_TYPEHASH(),
                account,
                operator,
                authExpiryTimestamp,
                signatureTimestamp,
                signatureDeadlineTimestamp
            )
        );
        signatureLookup[_hashTypedDataV4(structHash)] = keccak256(signature);
    }

    function isValidSignature(
        bytes32 hash,
        bytes memory signature
    ) external view returns (bytes4 magicValue) {
        if (signatureLookup[hash] == keccak256(signature)) {
            magicValue = this.isValidSignature.selector;
        }
    }
}

contract SetAccountOperatorPermitERC1271Test is Test {
    CreditVaultConnectorHarness internal cvc;

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
        cvc = new CreditVaultConnectorHarness();
    }

    function test_SetAccountOperatorPermitERC1271(
        address operator,
        uint40 authExpiry,
        bytes calldata signature,
        uint40 seed
    ) public {
        address signer = address(new Signer(cvc));

        vm.assume(!cvc.haveCommonOwner(signer, operator));
        vm.assume(authExpiry >= seed && authExpiry < type(uint40).max - 1);
        vm.assume(seed > 0 && seed < type(uint40).max - 10);
        vm.assume(signature.length > 0);
        vm.warp(seed);

        for (uint i = 0; i < 256; ++i) {
            address account = address(uint160(uint160(signer) ^ i));

            {
                uint40 expiryTimestamp = cvc
                    .getAccountOperatorAuthExpiryTimestamp(account, operator);
                (, uint40 lastSignatureTimestamp) = cvc
                    .getLastSignatureTimestamps(account, operator);
                assertEq(expiryTimestamp, 0);
                assertEq(lastSignatureTimestamp, 0);
            }

            if (i == 0) {
                vm.expectRevert(
                    CreditVaultConnector.CVC_AccountOwnerNotRegistered.selector
                );
                cvc.getAccountOwner(account);
            } else {
                assertEq(cvc.getAccountOwner(account), signer);
            }

            Signer(signer).setSignature(
                account,
                operator,
                authExpiry,
                uint40(block.timestamp),
                uint40(block.timestamp),
                signature
            );

            // authorize the operator
            if (i == 0) {
                vm.expectEmit(true, true, false, false, address(cvc));
                emit AccountsOwnerRegistered(cvc.getPrefix(signer), signer);
            }
            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(account, operator, authExpiry);
            vm.recordLogs();
            cvc.setAccountOperatorPermitERC1271(
                account,
                operator,
                authExpiry,
                uint40(block.timestamp),
                uint40(block.timestamp),
                signature,
                signer
            );
            Vm.Log[] memory logs = vm.getRecordedLogs();

            {
                assertTrue(i == 0 ? logs.length == 2 : logs.length == 1); // AccountsOwnerRegistered event is emitted only once
                uint40 expiryTimestamp = cvc
                    .getAccountOperatorAuthExpiryTimestamp(account, operator);
                (, uint40 lastSignatureTimestamp) = cvc
                    .getLastSignatureTimestamps(account, operator);
                assertEq(expiryTimestamp, authExpiry);
                assertEq(lastSignatureTimestamp, block.timestamp);
                assertEq(cvc.getAccountOwner(account), signer);
            }

            // it's not possible to carry out a reply attack
            vm.expectRevert(CreditVaultConnector.CVC_InvalidTimestamp.selector);
            cvc.setAccountOperatorPermitERC1271(
                account,
                operator,
                authExpiry,
                uint40(block.timestamp),
                uint40(block.timestamp),
                signature,
                signer
            );

            // early return if the operator is already enabled with the same expiry timestamp
            vm.warp(block.timestamp + 1);
            Signer(signer).setSignature(
                account,
                operator,
                authExpiry,
                uint40(block.timestamp),
                uint40(block.timestamp),
                signature
            );

            vm.recordLogs();
            cvc.setAccountOperatorPermitERC1271(
                account,
                operator,
                authExpiry,
                uint40(block.timestamp),
                uint40(block.timestamp),
                signature,
                signer
            );
            logs = vm.getRecordedLogs();

            {
                assertEq(logs.length, 0);
                uint40 expiryTimestamp = cvc
                    .getAccountOperatorAuthExpiryTimestamp(account, operator);
                (, uint40 lastSignatureTimestamp) = cvc
                    .getLastSignatureTimestamps(account, operator);
                assertEq(expiryTimestamp, authExpiry);
                assertEq(lastSignatureTimestamp, block.timestamp);
                assertEq(cvc.getAccountOwner(account), signer);
            }

            // change the authorization expiry timestamp
            vm.warp(block.timestamp + 1);
            Signer(signer).setSignature(
                account,
                operator,
                authExpiry + 1,
                uint40(block.timestamp),
                uint40(block.timestamp),
                signature
            );

            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(account, operator, authExpiry + 1);
            vm.recordLogs();
            cvc.setAccountOperatorPermitERC1271(
                account,
                operator,
                authExpiry + 1,
                uint40(block.timestamp),
                uint40(block.timestamp),
                signature,
                signer
            );
            logs = vm.getRecordedLogs();

            {
                assertEq(logs.length, 1);
                uint40 expiryTimestamp = cvc
                    .getAccountOperatorAuthExpiryTimestamp(account, operator);
                (, uint40 lastSignatureTimestamp) = cvc
                    .getLastSignatureTimestamps(account, operator);
                assertEq(expiryTimestamp, authExpiry + 1);
                assertEq(lastSignatureTimestamp, block.timestamp);
                assertEq(cvc.getAccountOwner(account), signer);
            }

            // deauthorize the operator
            vm.warp(block.timestamp + 1);
            Signer(signer).setSignature(
                account,
                operator,
                1,
                uint40(block.timestamp),
                uint40(block.timestamp),
                signature
            );

            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(account, operator, 1);
            vm.recordLogs();
            cvc.setAccountOperatorPermitERC1271(
                account,
                operator,
                1,
                uint40(block.timestamp),
                uint40(block.timestamp),
                signature,
                signer
            );
            logs = vm.getRecordedLogs();

            {
                assertEq(logs.length, 1);
                uint40 expiryTimestamp = cvc
                    .getAccountOperatorAuthExpiryTimestamp(account, operator);
                (, uint40 lastSignatureTimestamp) = cvc
                    .getLastSignatureTimestamps(account, operator);
                assertEq(expiryTimestamp, 1);
                assertEq(lastSignatureTimestamp, block.timestamp);
                assertEq(cvc.getAccountOwner(account), signer);
            }

            // early return if the operator is already deauthorized with the same timestamp
            vm.warp(block.timestamp + 1);
            Signer(signer).setSignature(
                account,
                operator,
                1,
                uint40(block.timestamp),
                uint40(block.timestamp),
                signature
            );

            vm.recordLogs();
            cvc.setAccountOperatorPermitERC1271(
                account,
                operator,
                1,
                uint40(block.timestamp),
                uint40(block.timestamp),
                signature,
                signer
            );
            logs = vm.getRecordedLogs();

            {
                assertEq(logs.length, 0);
                uint40 expiryTimestamp = cvc
                    .getAccountOperatorAuthExpiryTimestamp(account, operator);
                (, uint40 lastSignatureTimestamp) = cvc
                    .getLastSignatureTimestamps(account, operator);
                assertEq(expiryTimestamp, 1);
                assertEq(lastSignatureTimestamp, block.timestamp);
                assertEq(cvc.getAccountOwner(account), signer);
            }

            // set expiry timestamp to the current block if special value is used
            vm.warp(block.timestamp + 1);
            Signer(signer).setSignature(
                account,
                operator,
                type(uint40).max,
                uint40(block.timestamp),
                uint40(block.timestamp),
                signature
            );

            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(account, operator, block.timestamp);
            vm.recordLogs();
            cvc.setAccountOperatorPermitERC1271(
                account,
                operator,
                type(uint40).max,
                uint40(block.timestamp),
                uint40(block.timestamp),
                signature,
                signer
            );
            logs = vm.getRecordedLogs();

            {
                assertTrue(logs.length == 1);
                uint40 expiryTimestamp = cvc
                    .getAccountOperatorAuthExpiryTimestamp(account, operator);
                (, uint40 lastSignatureTimestamp) = cvc
                    .getLastSignatureTimestamps(account, operator);
                assertEq(expiryTimestamp, block.timestamp);
                assertEq(lastSignatureTimestamp, block.timestamp);
                assertEq(cvc.getAccountOwner(account), signer);
            }
        }
    }

    function test_RevertIfSignerNotAuthorized_SetAccountOperatorPermitERC1271(
        address operator,
        bytes calldata signature
    ) public {
        address signer = address(new Signer(cvc));
        address signer2 = address(new Signer(cvc));
        vm.assume(!cvc.haveCommonOwner(signer, operator));
        vm.assume(!cvc.haveCommonOwner(signer, signer2));
        vm.assume(signature.length > 0);

        address account = address(uint160(uint160(signer) ^ 255));
        Signer(signer).setSignature(
            account,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature
        );

        Signer(signer2).setSignature(
            account,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature
        );

        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperatorPermitERC1271(
            account,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer2
        );

        vm.warp(block.timestamp + 1);
        account = address(uint160(uint160(signer) ^ 256));
        Signer(signer).setSignature(
            account,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature
        );

        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperatorPermitERC1271(
            account,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );

        // succeeds if signer is authorized
        account = address(uint160(uint160(signer) ^ 255));
        Signer(signer).setSignature(
            account,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature
        );

        cvc.setAccountOperatorPermitERC1271(
            account,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );

        // reverts if registered owner doesn't validate the signature
        vm.warp(block.timestamp + 1);
        Signer(signer).setSignature(
            account,
            operator,
            1,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature
        );

        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperatorPermitERC1271(
            account,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );

        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperatorPermitERC1271(
            account,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer2
        );
    }

    function test_RevertIfOperatorIsOwnersAccount_SetAccountOperatorPermitERC1271(
        uint8 subAccountId,
        bytes calldata signature
    ) public {
        vm.assume(signature.length > 0);

        address signer = address(new Signer(cvc));
        address operator = address(uint160(uint160(signer) ^ subAccountId));

        Signer(signer).setSignature(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature
        );

        vm.expectRevert(CreditVaultConnector.CVC_InvalidAddress.selector);
        cvc.setAccountOperatorPermitERC1271(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );
    }

    function test_RevertIfSignatureTimestampInThePast_SetAccountOperatorPermitERC1271(
        address operator,
        uint40 seed,
        bytes calldata signature
    ) public {
        address signer = address(new Signer(cvc));
        vm.assume(!cvc.haveCommonOwner(signer, operator));
        vm.assume(seed > 0 && seed < type(uint40).max);
        vm.assume(signature.length > 0);

        vm.warp(seed);

        // succeeds as the first signature is not in the past
        uint40 lastSignatureTimestamp = uint40(block.timestamp);
        Signer(signer).setSignature(
            signer,
            operator,
            0,
            lastSignatureTimestamp,
            uint40(block.timestamp),
            signature
        );
        cvc.setAccountOperatorPermitERC1271(
            signer,
            operator,
            0,
            lastSignatureTimestamp,
            uint40(block.timestamp),
            signature,
            signer
        );

        // time elapses
        vm.warp(block.timestamp + 1);

        // this signature is in the past hence it reverts
        Signer(signer).setSignature(
            signer,
            operator,
            0,
            lastSignatureTimestamp,
            uint40(block.timestamp),
            signature
        );
        vm.expectRevert(CreditVaultConnector.CVC_InvalidTimestamp.selector);
        cvc.setAccountOperatorPermitERC1271(
            signer,
            operator,
            0,
            lastSignatureTimestamp,
            uint40(block.timestamp),
            signature,
            signer
        );

        // this signature is even more in the past hence it reverts
        Signer(signer).setSignature(
            signer,
            operator,
            0,
            0,
            uint40(block.timestamp),
            signature
        );
        vm.expectRevert(CreditVaultConnector.CVC_InvalidTimestamp.selector);
        cvc.setAccountOperatorPermitERC1271(
            signer,
            operator,
            0,
            0,
            uint40(block.timestamp),
            signature,
            signer
        );

        // succeeds if signature timestamp is not in the past
        Signer(signer).setSignature(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature
        );
        cvc.setAccountOperatorPermitERC1271(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );
    }

    function test_RevertIfSignatureTimestampInTheFuture_SetAccountOperatorPermitERC1271(
        address operator,
        uint40 seed,
        bytes calldata signature
    ) public {
        address signer = address(new Signer(cvc));
        vm.assume(!cvc.haveCommonOwner(signer, operator));
        vm.assume(seed > 0 && seed < type(uint40).max);
        vm.assume(signature.length > 0);

        vm.warp(seed);

        Signer(signer).setSignature(
            signer,
            operator,
            0,
            uint40(block.timestamp + 1),
            uint40(block.timestamp),
            signature
        );
        vm.expectRevert(CreditVaultConnector.CVC_InvalidTimestamp.selector);
        cvc.setAccountOperatorPermitERC1271(
            signer,
            operator,
            0,
            uint40(block.timestamp + 1),
            uint40(block.timestamp),
            signature,
            signer
        );

        // succeeds if signature timestamp is not in the future
        Signer(signer).setSignature(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature
        );
        cvc.setAccountOperatorPermitERC1271(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );
    }

    function test_RevertIfSignatureDeadlineMissed_SetAccountOperatorPermitERC1271(
        address operator,
        uint40 seed,
        bytes calldata signature
    ) public {
        address signer = address(new Signer(cvc));
        vm.assume(!cvc.haveCommonOwner(signer, operator));
        vm.assume(seed > 0);
        vm.assume(signature.length > 0);

        vm.warp(seed);

        Signer(signer).setSignature(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp - 1),
            signature
        );

        vm.expectRevert(CreditVaultConnector.CVC_InvalidTimestamp.selector);
        cvc.setAccountOperatorPermitERC1271(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp - 1),
            signature,
            signer
        );

        // succeeds if deadline is not missed
        Signer(signer).setSignature(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature
        );
        cvc.setAccountOperatorPermitERC1271(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );
    }

    function test_RevertIfInvalidSignature_SetAccountOperatorPermitERC1271(
        address operator,
        uint40 seed,
        bytes calldata signature
    ) public {
        address signer = address(new Signer(cvc));

        vm.assume(uint160(operator) != type(uint160).max);
        vm.assume(!cvc.haveCommonOwner(signer, operator));
        vm.assume(seed > 0 && seed < type(uint40).max - 10);
        vm.assume(signature.length > 0);
        vm.warp(seed);

        Signer(signer).setSignature(
            address(uint160(signer) + 1),
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature
        );
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperatorPermitERC1271(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );

        Signer(signer).setSignature(
            signer,
            address(uint160(operator) + 1),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature
        );
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperatorPermitERC1271(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );

        Signer(signer).setSignature(
            signer,
            operator,
            1,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature
        );
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperatorPermitERC1271(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );

        Signer(signer).setSignature(
            signer,
            operator,
            0,
            uint40(block.timestamp + 1),
            uint40(block.timestamp),
            signature
        );
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperatorPermitERC1271(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );

        Signer(signer).setSignature(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp + 1),
            signature
        );

        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperatorPermitERC1271(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );

        // succeeds if signature is valid
        Signer(signer).setSignature(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature
        );
        cvc.setAccountOperatorPermitERC1271(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );

        vm.warp(block.timestamp + 1);
        Signer(signer).setSignature(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature
        );
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.setAccountOperatorPermitERC1271(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            "",
            signer
        );
    }

    function test_RevertIfPermitInvalidated_SetAccountOperatorPermitERC1271(
        address operator,
        uint40 seed,
        bytes calldata signature1,
        bytes calldata signature2
    ) public {
        address signer = address(new Signer(cvc));
        vm.assume(uint160(operator) != type(uint160).max);
        vm.assume(!cvc.haveCommonOwner(signer, operator));
        vm.assume(seed > 0 && seed < type(uint40).max - 10);
        vm.assume(signature1.length > 0);
        vm.assume(signature2.length > 0);

        vm.warp(seed);
        Signer(signer).setSignature(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature1
        );

        Signer(signer).setSignature(
            signer,
            address(uint160(operator) + 1),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature2
        );

        vm.prank(signer);
        cvc.invalidateAllPermits();

        vm.expectRevert(CreditVaultConnector.CVC_InvalidTimestamp.selector);
        cvc.setAccountOperatorPermitERC1271(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature1,
            signer
        );
        vm.expectRevert(CreditVaultConnector.CVC_InvalidTimestamp.selector);
        cvc.setAccountOperatorPermitERC1271(
            signer,
            address(uint160(operator) + 1),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature2,
            signer
        );

        vm.warp(block.timestamp + 1);
        Signer(signer).setSignature(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature1
        );

        Signer(signer).setSignature(
            signer,
            address(uint160(operator) + 1),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature2
        );

        vm.prank(signer);
        cvc.invalidateAccountOperatorPermits(signer, operator);

        // only one permit is invalid
        vm.expectRevert(CreditVaultConnector.CVC_InvalidTimestamp.selector);
        cvc.setAccountOperatorPermitERC1271(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature1,
            signer
        );
        cvc.setAccountOperatorPermitERC1271(
            signer,
            address(uint160(operator) + 1),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature2,
            signer
        );

        // succeeds if permit is not invalidated
        vm.warp(block.timestamp + 1);
        Signer(signer).setSignature(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature1
        );
        cvc.setAccountOperatorPermitERC1271(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature1,
            signer
        );

        // reverts if replayed
        vm.expectRevert(CreditVaultConnector.CVC_InvalidTimestamp.selector);
        cvc.setAccountOperatorPermitERC1271(
            signer,
            operator,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature1,
            signer
        );
    }
}
