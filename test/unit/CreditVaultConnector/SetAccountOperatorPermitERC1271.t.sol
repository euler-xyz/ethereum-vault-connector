// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../utils/mocks/Operator.sol";
import "../../../src/test/CreditVaultConnectorHarness.sol";
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
        address account,
        address operator,
        bytes calldata operatorData,
        uint40 authExpiryTimestamp,
        uint40 signatureTimestamp,
        uint40 signatureDeadlineTimestamp
    ) external {
        bytes32 structHash = keccak256(
            abi.encode(
                cvc.OPERATOR_PERMIT_TYPEHASH(),
                account,
                operator,
                keccak256(operatorData),
                authExpiryTimestamp,
                signatureTimestamp,
                signatureDeadlineTimestamp
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

contract installAccountOperatorPermitERC1271Test is Test {
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

    function test_installAccountOperatorPermitERC1271(
        bytes memory operatorData,
        uint16 value,
        uint40 authExpiry,
        bytes calldata signature,
        uint40 seed
    ) public {
        address signer = address(new Signer(cvc));
        address payable operator = payable(new Operator());

        vm.assume(!cvc.haveCommonOwner(signer, operator));
        vm.assume(
            bytes4(operatorData) != 0xc41e79ed &&
                bytes4(operatorData) != 0xb79bb2d7 &&
                bytes4(operatorData) != 0x1234458c
        );
        vm.assume(authExpiry >= seed && authExpiry < type(uint40).max - 1);
        vm.assume(seed > 10 && seed < type(uint40).max - 10);
        vm.assume(signature.length > 0);
        vm.assume(value < type(uint16).max - 10);

        vm.deal(msg.sender, type(uint128).max);

        Signer(signer).setSignatureHash(signature);

        for (uint i = 0; i < 256; ++i) {
            vm.warp(seed);

            address account = address(uint160(uint160(signer) ^ i));

            {
                (
                    uint40 expiryTimestamp,
                    uint40 lastSignatureTimestamp,,
                ) = cvc.getAccountOperatorContext(account, operator);
                assertEq(expiryTimestamp, 0);
                assertEq(lastSignatureTimestamp, 0);
            }

            Operator(operator).clearFallbackCalled();
            Operator(operator).setExpectedHash(operatorData);
            Operator(operator).setExpectedValue(value);
            Operator(operator).setExpectedSingleOperatorCallAuth(false);

            if (i == 0) {
                vm.expectRevert(
                    CreditVaultConnector.CVC_AccountOwnerNotRegistered.selector
                );
                cvc.getAccountOwner(account);
            } else {
                assertEq(cvc.getAccountOwner(account), signer);
            }

            Signer(signer).setPermitHash(
                account,
                operator,
                operatorData,
                authExpiry,
                uint40(block.timestamp - 5),
                uint40(block.timestamp)
            );

            // authorize the operator
            if (i == 0) {
                vm.expectEmit(true, true, false, false, address(cvc));
                emit AccountsOwnerRegistered(cvc.getPrefix(signer), signer);
            }
            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(account, operator, authExpiry);
            vm.recordLogs();
            cvc.installAccountOperatorPermitERC1271{value: value}(
                account,
                operator,
                operatorData,
                authExpiry,
                uint40(block.timestamp - 5),
                uint40(block.timestamp),
                signature,
                signer
            );

            {
                Vm.Log[] memory logs = vm.getRecordedLogs();
                assertTrue(i == 0 ? logs.length == 2 : logs.length == 1); // AccountsOwnerRegistered event is emitted only once
                (
                    uint40 expiryTimestamp,
                    uint40 lastSignatureTimestamp,,
                ) = cvc.getAccountOperatorContext(account, operator);
                assertEq(expiryTimestamp, authExpiry);
                assertEq(lastSignatureTimestamp, block.timestamp - 5);
                assertEq(
                    Operator(operator).fallbackCalled(),
                    operatorData.length > 0 ? true : false
                );
                assertEq(cvc.getAccountOwner(account), signer);
            }

            // it's not possible to carry out a reply attack
            vm.expectRevert(CreditVaultConnector.CVC_InvalidTimestamp.selector);
            cvc.installAccountOperatorPermitERC1271{value: value}(
                account,
                operator,
                operatorData,
                authExpiry,
                uint40(block.timestamp - 5),
                uint40(block.timestamp),
                signature,
                signer
            );

            // don't emit the event if the operator is already enabled with the same expiry timestamp
            Operator(operator).clearFallbackCalled();
            Operator(operator).setExpectedHash(
                bytes(abi.encode(operatorData, "1"))
            );
            Operator(operator).setExpectedValue(value + 1);
            Operator(operator).setExpectedSingleOperatorCallAuth(false);

            vm.warp(block.timestamp + 1);
            Signer(signer).setPermitHash(
                account,
                operator,
                bytes(abi.encode(operatorData, "1")),
                authExpiry,
                uint40(block.timestamp - 3),
                uint40(block.timestamp)
            );

            vm.recordLogs();
            cvc.installAccountOperatorPermitERC1271{value: value + 1}(
                account,
                operator,
                bytes(abi.encode(operatorData, "1")),
                authExpiry,
                uint40(block.timestamp - 3),
                uint40(block.timestamp),
                signature,
                signer
            );

            {
                Vm.Log[] memory logs = vm.getRecordedLogs();
                assertEq(logs.length, 0);
                (
                    uint40 expiryTimestamp,
                    uint40 lastSignatureTimestamp,,
                ) = cvc.getAccountOperatorContext(account, operator);
                assertEq(expiryTimestamp, authExpiry);
                assertEq(lastSignatureTimestamp, block.timestamp - 3);
                assertEq(Operator(operator).fallbackCalled(), true);
                assertEq(cvc.getAccountOwner(account), signer);
            }

            // change the authorization expiry timestamp
            Operator(operator).clearFallbackCalled();
            Operator(operator).setExpectedHash(
                bytes(abi.encode(operatorData, "2"))
            );
            Operator(operator).setExpectedValue(value + 2);
            Operator(operator).setExpectedSingleOperatorCallAuth(false);

            vm.warp(block.timestamp + 1);
            Signer(signer).setPermitHash(
                account,
                operator,
                bytes(abi.encode(operatorData, "2")),
                authExpiry + 1,
                uint40(block.timestamp - 2),
                uint40(block.timestamp)
            );

            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(account, operator, authExpiry + 1);
            vm.recordLogs();
            cvc.installAccountOperatorPermitERC1271{value: value + 2}(
                account,
                operator,
                bytes(abi.encode(operatorData, "2")),
                authExpiry + 1,
                uint40(block.timestamp - 2),
                uint40(block.timestamp),
                signature,
                signer
            );

            {
                Vm.Log[] memory logs = vm.getRecordedLogs();
                assertEq(logs.length, 1);
                (
                    uint40 expiryTimestamp,
                    uint40 lastSignatureTimestamp,,
                ) = cvc.getAccountOperatorContext(account, operator);
                assertEq(expiryTimestamp, authExpiry + 1);
                assertEq(lastSignatureTimestamp, block.timestamp - 2);
                assertEq(Operator(operator).fallbackCalled(), true);
                assertEq(cvc.getAccountOwner(account), signer);
            }

            // deauthorize the operator
            Operator(operator).clearFallbackCalled();
            Operator(operator).setExpectedHash(
                bytes(abi.encode(operatorData, "3"))
            );
            Operator(operator).setExpectedValue(value + 3);
            Operator(operator).setExpectedSingleOperatorCallAuth(false);

            vm.warp(block.timestamp + 1);
            Signer(signer).setPermitHash(
                account,
                operator,
                bytes(abi.encode(operatorData, "3")),
                1,
                uint40(block.timestamp),
                uint40(block.timestamp)
            );

            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(account, operator, 1);
            vm.recordLogs();
            cvc.installAccountOperatorPermitERC1271{value: value + 3}(
                account,
                operator,
                bytes(abi.encode(operatorData, "3")),
                1,
                uint40(block.timestamp),
                uint40(block.timestamp),
                signature,
                signer
            );

            {
                Vm.Log[] memory logs = vm.getRecordedLogs();
                assertEq(logs.length, 1);
                (
                    uint40 expiryTimestamp,
                    uint40 lastSignatureTimestamp,,
                ) = cvc.getAccountOperatorContext(account, operator);
                assertEq(expiryTimestamp, 1);
                assertEq(lastSignatureTimestamp, block.timestamp);
                assertEq(Operator(operator).fallbackCalled(), true);
                assertEq(cvc.getAccountOwner(account), signer);
            }

            // don't emit the event if the operator is already deauthorized with the same timestamp
            Operator(operator).clearFallbackCalled();
            Operator(operator).setExpectedHash(
                bytes(abi.encode(operatorData, "4"))
            );
            Operator(operator).setExpectedValue(value + 4);
            Operator(operator).setExpectedSingleOperatorCallAuth(false);

            vm.warp(block.timestamp + 1);
            Signer(signer).setPermitHash(
                account,
                operator,
                bytes(abi.encode(operatorData, "4")),
                1,
                uint40(block.timestamp),
                uint40(block.timestamp)
            );

            vm.recordLogs();
            cvc.installAccountOperatorPermitERC1271{value: value + 4}(
                account,
                operator,
                bytes(abi.encode(operatorData, "4")),
                1,
                uint40(block.timestamp),
                uint40(block.timestamp),
                signature,
                signer
            );

            {
                Vm.Log[] memory logs = vm.getRecordedLogs();
                assertEq(logs.length, 0);
                (
                    uint40 expiryTimestamp,
                    uint40 lastSignatureTimestamp,,
                ) = cvc.getAccountOperatorContext(account, operator);
                assertEq(expiryTimestamp, 1);
                assertEq(lastSignatureTimestamp, block.timestamp);
                assertEq(Operator(operator).fallbackCalled(), true);
                assertEq(cvc.getAccountOwner(account), signer);
            }

            // approve the operator only for the timebeing of the operator callback if the special value is used
            Operator(operator).clearFallbackCalled();
            Operator(operator).setExpectedHash(
                bytes(abi.encode(operatorData, "5"))
            );
            Operator(operator).setExpectedValue(value + 5);
            Operator(operator).setExpectedSingleOperatorCallAuth(true);

            vm.warp(block.timestamp + 1);
            Signer(signer).setPermitHash(
                account,
                operator,
                bytes(abi.encode(operatorData, "5")),
                0,
                uint40(block.timestamp),
                uint40(block.timestamp)
            );

            vm.expectEmit(true, true, false, true, address(cvc));
            emit AccountOperatorAuthorized(account, operator, 0);
            vm.recordLogs();
            cvc.installAccountOperatorPermitERC1271{value: value + 5}(
                account,
                operator,
                bytes(abi.encode(operatorData, "5")),
                0,
                uint40(block.timestamp),
                uint40(block.timestamp),
                signature,
                signer
            );

            {
                Vm.Log[] memory logs = vm.getRecordedLogs();
                assertTrue(logs.length == 1);
                (
                    uint40 expiryTimestamp,
                    uint40 lastSignatureTimestamp,,
                ) = cvc.getAccountOperatorContext(account, operator);
                assertEq(expiryTimestamp, 0);
                assertEq(lastSignatureTimestamp, block.timestamp);
                assertEq(Operator(operator).fallbackCalled(), true);
                assertEq(cvc.getAccountOwner(account), signer);
            }
        }
    }

    function test_BatchCallback_installAccountOperatorPermitERC1271(
        bytes calldata signature,
        address collateral,
        uint40 seed
    ) public {
        address alice = address(new Signer(cvc));
        address operator = address(new OperatorBatchCallback());

        vm.assume(signature.length > 0);
        vm.assume(!cvc.haveCommonOwner(alice, operator));
        vm.assume(seed > 10 && seed < type(uint40).max - 10);

        vm.warp(seed);

        ICVC.BatchItem[] memory items = new ICVC.BatchItem[](1);
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = address(cvc);
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(
            cvc.enableCollateral.selector,
            alice,
            collateral
        );
        bytes memory operatorData = abi.encodeWithSelector(
            OperatorBatchCallback.callBatch.selector,
            address(cvc),
            items
        );

        Signer(alice).setSignatureHash(signature);
        Signer(alice).setPermitHash(
            alice,
            operator,
            operatorData,
            0,
            uint40(block.timestamp - 1),
            uint40(block.timestamp)
        );

        cvc.installAccountOperatorPermitERC1271(
            alice,
            operator,
            operatorData,
            0,
            uint40(block.timestamp - 1),
            uint40(block.timestamp),
            signature,
            alice
        );

        (uint40 expiryTimestamp, uint40 lastSignatureTimestamp,,) = cvc
            .getAccountOperatorContext(alice, operator);
        assertEq(cvc.isCollateralEnabled(alice, collateral), true);
        assertEq(expiryTimestamp, 0);
        assertEq(lastSignatureTimestamp, block.timestamp - 1);
    }

    function test_RevertIfOperatorCallReentrancy_installAccountOperatorPermitERC1271(
        bytes calldata signature,
        uint40 seed
    ) public {
        address signer = address(new Signer(cvc));
        address payable operator = payable(new OperatorMaliciousERC1271());

        vm.assume(uint160(address(operator)) != type(uint160).max);
        vm.assume(!cvc.haveCommonOwner(signer, operator));
        vm.assume(seed > 0 && seed < type(uint40).max - 10);
        vm.assume(signature.length > 0);
        vm.warp(seed);

        Signer(signer).setSignatureHash(signature);

        // CVC_OperatorCallFailure is expected due to OperatorMaliciousERC1271 reverting.
        // look at OperatorMaliciousERC1271 implementation for details.
        bytes memory operatorData = abi.encode(signer, operator);
        Signer(signer).setPermitHash(
            signer,
            operator,
            operatorData,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );
        vm.expectRevert(CreditVaultConnector.CVC_OperatorCallFailure.selector);
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator,
            operatorData,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );

        // succeeds if OperatorMaliciousERC1271 tries to install operator for different account.
        // look at OperatorMaliciousERC1271 implementation for details.
        operatorData = abi.encode(address(uint160(signer) ^ 1), operator);
        Signer(signer).setPermitHash(
            signer,
            operator,
            operatorData,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator,
            operatorData,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );

        vm.warp(block.timestamp + 1);

        // succeeds if OperatorMaliciousERC1271 tries to install different operator for the account
        // look at OperatorMaliciousERC1271 implementation for details.
        operatorData = abi.encode(
            signer,
            address(uint160(address(operator)) ^ 1)
        );
        Signer(signer).setPermitHash(
            signer,
            operator,
            operatorData,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator,
            operatorData,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );
    }

    function test_RevertIfSignerNotAuthorized_installAccountOperatorPermitERC1271(
        address operator,
        bytes calldata signature
    ) public {
        address signer = address(new Signer(cvc));
        address signer2 = address(new Signer(cvc));
        vm.assume(!cvc.haveCommonOwner(signer, operator));
        vm.assume(!cvc.haveCommonOwner(signer, signer2));
        vm.assume(signature.length > 0);

        address account = address(uint160(uint160(signer) ^ 255));

        Signer(signer).setSignatureHash(signature);
        Signer(signer).setPermitHash(
            account,
            operator,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );

        Signer(signer2).setSignatureHash(signature);
        Signer(signer2).setPermitHash(
            account,
            operator,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );

        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.installAccountOperatorPermitERC1271(
            account,
            operator,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer2 // signer2 is not sub-account of signer
        );

        vm.warp(block.timestamp + 1);
        account = address(uint160(uint160(signer) ^ 256));
        Signer(signer).setPermitHash(
            account,
            operator,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );

        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.installAccountOperatorPermitERC1271(
            account,
            operator,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );

        // succeeds if signer is authorized
        account = address(uint160(uint160(signer) ^ 255));
        Signer(signer).setPermitHash(
            account,
            operator,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );

        cvc.installAccountOperatorPermitERC1271(
            account,
            operator,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );

        // reverts if registered owner doesn't validate the signature
        vm.warp(block.timestamp + 1);
        Signer(signer).setPermitHash(
            account,
            operator,
            bytes(""),
            1,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );

        Signer(signer2).setPermitHash(
            account,
            operator,
            bytes(""),
            1,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );

        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.installAccountOperatorPermitERC1271(
            account,
            operator,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );

        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.installAccountOperatorPermitERC1271(
            account,
            operator,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer2
        );
    }

    function test_RevertIfOperatorIsOwnersAccount_installAccountOperatorPermitERC1271(
        uint8 subAccountId,
        bytes calldata signature
    ) public {
        vm.assume(signature.length > 0);

        address signer = address(new Signer(cvc));
        address operator = address(uint160(uint160(signer) ^ subAccountId));

        Signer(signer).setSignatureHash(signature);
        Signer(signer).setPermitHash(
            signer,
            operator,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );

        vm.expectRevert(CreditVaultConnector.CVC_InvalidAddress.selector);
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );
    }

    function test_RevertIfSignatureTimestampInThePast_installAccountOperatorPermitERC1271(
        address operator,
        uint40 seed,
        bytes calldata signature
    ) public {
        address signer = address(new Signer(cvc));
        vm.assume(!cvc.haveCommonOwner(signer, operator));
        vm.assume(seed > 0 && seed < type(uint40).max);
        vm.assume(signature.length > 0);

        vm.warp(seed);

        Signer(signer).setSignatureHash(signature);

        // succeeds as the first signature is not in the past
        uint40 lastSignatureTimestamp = uint40(block.timestamp);
        Signer(signer).setPermitHash(
            signer,
            operator,
            bytes(""),
            0,
            lastSignatureTimestamp,
            uint40(block.timestamp)
        );
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator,
            bytes(""),
            0,
            lastSignatureTimestamp,
            uint40(block.timestamp),
            signature,
            signer
        );

        // time elapses
        vm.warp(block.timestamp + 1);

        // this signature is in the past hence it reverts
        Signer(signer).setPermitHash(
            signer,
            operator,
            bytes(""),
            0,
            lastSignatureTimestamp,
            uint40(block.timestamp)
        );
        vm.expectRevert(CreditVaultConnector.CVC_InvalidTimestamp.selector);
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator,
            bytes(""),
            0,
            lastSignatureTimestamp,
            uint40(block.timestamp),
            signature,
            signer
        );

        // this signature is even more in the past hence it reverts
        Signer(signer).setPermitHash(
            signer,
            operator,
            bytes(""),
            0,
            0,
            uint40(block.timestamp)
        );
        vm.expectRevert(CreditVaultConnector.CVC_InvalidTimestamp.selector);
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator,
            bytes(""),
            0,
            0,
            uint40(block.timestamp),
            signature,
            signer
        );

        // succeeds if signature timestamp is not in the past
        Signer(signer).setPermitHash(
            signer,
            operator,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );
    }

    function test_RevertIfSignatureTimestampInTheFuture_installAccountOperatorPermitERC1271(
        address operator,
        uint40 seed,
        bytes calldata signature
    ) public {
        address signer = address(new Signer(cvc));
        vm.assume(!cvc.haveCommonOwner(signer, operator));
        vm.assume(seed > 0 && seed < type(uint40).max);
        vm.assume(signature.length > 0);

        vm.warp(seed);

        Signer(signer).setSignatureHash(signature);

        Signer(signer).setPermitHash(
            signer,
            operator,
            bytes(""),
            0,
            uint40(block.timestamp + 1),
            uint40(block.timestamp)
        );
        vm.expectRevert(CreditVaultConnector.CVC_InvalidTimestamp.selector);
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator,
            bytes(""),
            0,
            uint40(block.timestamp + 1),
            uint40(block.timestamp),
            signature,
            signer
        );

        // succeeds if signature timestamp is not in the future
        Signer(signer).setPermitHash(
            signer,
            operator,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );
    }

    function test_RevertIfSignatureDeadlineMissed_installAccountOperatorPermitERC1271(
        address operator,
        uint40 seed,
        bytes calldata signature
    ) public {
        address signer = address(new Signer(cvc));
        vm.assume(!cvc.haveCommonOwner(signer, operator));
        vm.assume(seed > 0);
        vm.assume(signature.length > 0);

        vm.warp(seed);

        Signer(signer).setSignatureHash(signature);

        Signer(signer).setPermitHash(
            signer,
            operator,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp - 1)
        );

        vm.expectRevert(CreditVaultConnector.CVC_InvalidTimestamp.selector);
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp - 1),
            signature,
            signer
        );

        // succeeds if deadline is not missed
        Signer(signer).setPermitHash(
            signer,
            operator,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );
    }

    function test_RevertIfInvalidSignature_installAccountOperatorPermitERC1271(
        bytes memory operatorData,
        uint40 seed,
        bytes calldata signature
    ) public {
        address signer = address(new Signer(cvc));
        address payable operator = payable(new Operator());

        vm.assume(uint160(address(operator)) != type(uint160).max);
        vm.assume(!cvc.haveCommonOwner(signer, operator));
        vm.assume(
            bytes4(operatorData) != 0xc41e79ed &&
                bytes4(operatorData) != 0xb79bb2d7 &&
                bytes4(operatorData) != 0x1234458c
        );
        vm.assume(seed > 0 && seed < type(uint40).max - 10);
        vm.assume(signature.length > 0);
        vm.warp(seed);

        Operator(operator).setExpectedHash(operatorData);
        Operator(operator).setExpectedSingleOperatorCallAuth(true);

        Signer(signer).setSignatureHash(signature);

        Signer(signer).setPermitHash(
            address(uint160(signer) + 1),
            operator,
            operatorData,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator,
            operatorData,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );

        Signer(signer).setPermitHash(
            signer,
            address(uint160(address(operator)) + 1),
            operatorData,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator,
            operatorData,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );

        Signer(signer).setPermitHash(
            signer,
            operator,
            abi.encode(operatorData, "1"),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator,
            operatorData,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );

        Signer(signer).setPermitHash(
            signer,
            operator,
            operatorData,
            1,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator,
            operatorData,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );

        Signer(signer).setPermitHash(
            signer,
            operator,
            operatorData,
            0,
            uint40(block.timestamp + 1),
            uint40(block.timestamp)
        );
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator,
            operatorData,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );

        Signer(signer).setPermitHash(
            signer,
            operator,
            operatorData,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp + 1)
        );

        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator,
            operatorData,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );

        // succeeds if signature is valid
        Signer(signer).setPermitHash(
            signer,
            operator,
            operatorData,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator,
            operatorData,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature,
            signer
        );

        vm.warp(block.timestamp + 1);
        Signer(signer).setPermitHash(
            signer,
            operator,
            operatorData,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );
        vm.expectRevert(CreditVaultConnector.CVC_NotAuthorized.selector);
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator,
            operatorData,
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            bytes(""),
            signer
        );
    }

    function test_RevertIfPermitInvalidated_installAccountOperatorPermitERC1271(
        uint40 seed,
        bytes calldata signature1,
        bytes calldata signature2
    ) public {
        address signer = address(new Signer(cvc));
        address payable operator1 = payable(new Operator());
        address payable operator2 = payable(new Operator());
        vm.assume(uint160(address(operator1)) != type(uint160).max);
        vm.assume(uint160(address(operator2)) != type(uint160).max);
        vm.assume(!cvc.haveCommonOwner(signer, operator1));
        vm.assume(!cvc.haveCommonOwner(signer, operator2));
        vm.assume(seed > 0 && seed < type(uint40).max - 10);
        vm.assume(signature1.length > 0);
        vm.assume(signature2.length > 0);

        vm.warp(seed);

        // both permits invalid
        vm.prank(signer);
        cvc.invalidateAllPermits();

        Signer(signer).setSignatureHash(signature1);
        Signer(signer).setPermitHash(
            signer,
            operator1,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );
        vm.expectRevert(CreditVaultConnector.CVC_InvalidTimestamp.selector);
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator1,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature1,
            signer
        );

        Signer(signer).setSignatureHash(signature2);
        Signer(signer).setPermitHash(
            signer,
            operator2,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );
        vm.expectRevert(CreditVaultConnector.CVC_InvalidTimestamp.selector);
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator2,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature2,
            signer
        );

        vm.warp(block.timestamp + 1);

        // only one permit is invalid
        vm.prank(signer);
        cvc.invalidateAccountOperatorPermits(signer, operator1);

        Signer(signer).setSignatureHash(signature1);
        Signer(signer).setPermitHash(
            signer,
            operator1,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );
        vm.expectRevert(CreditVaultConnector.CVC_InvalidTimestamp.selector);
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator1,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature1,
            signer
        );

        Signer(signer).setSignatureHash(signature2);
        Signer(signer).setPermitHash(
            signer,
            operator2,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator2,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature2,
            signer
        );

        vm.warp(block.timestamp + 1);

        // succeeds if permit is not invalidated
        Signer(signer).setSignatureHash(signature1);
        Signer(signer).setPermitHash(
            signer,
            operator1,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp)
        );
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator1,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature1,
            signer
        );

        // reverts if replayed
        vm.expectRevert(CreditVaultConnector.CVC_InvalidTimestamp.selector);
        cvc.installAccountOperatorPermitERC1271(
            signer,
            operator1,
            bytes(""),
            0,
            uint40(block.timestamp),
            uint40(block.timestamp),
            signature1,
            signer
        );
    }
}
