// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../../../src/utils/EVCUtil.sol";
import "../../../src/interfaces/IERC1271.sol";
import "../../../src/interfaces/IVault.sol";
import "../../evc/EthereumVaultConnectorHarness.sol";

/// @dev Answers `isValidSignature` through its fallback, as a contract forwarding arbitrary calldata does, and accepts
/// the signature when the selected EVCUtil helper returns `account`.
contract ERC1271Client is EVCUtil {
    enum Authentication {
        None,
        MsgSender,
        MsgSenderForBorrow,
        MsgSenderOnlyEVCAccount,
        MsgSenderOnlyEVCAccountOwner
    }

    address internal immutable account;
    Authentication internal authentication;

    constructor(address _evc, address _account) EVCUtil(_evc) {
        account = _account;
    }

    function setAuthentication(Authentication _authentication) external {
        authentication = _authentication;
    }

    function checkAccountStatus(address, address[] calldata) external pure returns (bytes4) {
        return IVault.checkAccountStatus.selector;
    }

    fallback(bytes calldata) external returns (bytes memory) {
        address sender = account;

        if (authentication == Authentication.MsgSender) {
            sender = _msgSender();
        } else if (authentication == Authentication.MsgSenderForBorrow) {
            sender = _msgSenderForBorrow();
        } else if (authentication == Authentication.MsgSenderOnlyEVCAccount) {
            sender = _msgSenderOnlyEVCAccount();
        } else if (authentication == Authentication.MsgSenderOnlyEVCAccountOwner) {
            sender = _msgSenderOnlyEVCAccountOwner();
        }

        return abi.encode(sender == account ? IERC1271.isValidSignature.selector : bytes4(0));
    }
}

contract ERC1271Signer is EVCUtil {
    address internal immutable account;

    constructor(address _evc, address _account) EVCUtil(_evc) {
        account = _account;
    }

    function isValidSignature(bytes32, bytes calldata) external view returns (bytes4) {
        return _msgSender() == account ? IERC1271.isValidSignature.selector : bytes4(0);
    }
}

contract ForwardingProxy {
    address internal immutable implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    fallback() external {
        address _implementation = implementation;

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), _implementation, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

/// @dev Reads the execution context without EVCUtil and accepts the signature when it holds `account`.
contract ContextReadingSigner {
    IEVC internal immutable evc;
    address internal immutable account;

    constructor(IEVC _evc, address _account) {
        evc = _evc;
        account = _account;
    }

    function isValidSignature(bytes32, bytes calldata) external view returns (bytes4) {
        (address onBehalfOfAccount,) = evc.getCurrentOnBehalfOfAccount(address(0));
        return onBehalfOfAccount == account ? IERC1271.isValidSignature.selector : bytes4(0);
    }
}

/// @dev Submits a permit from inside an EVC call to itself, whose onBehalfOfAccount the EVC does not authenticate.
contract NestedPermitCaller {
    IEVC internal immutable evc;

    constructor(IEVC _evc) {
        evc = _evc;
    }

    function run(address onBehalfOfAccount, address signer, bytes calldata data) external {
        evc.call(address(this), onBehalfOfAccount, 0, abi.encodeCall(this.submitPermit, (signer, data)));
    }

    function submitPermit(address signer, bytes calldata data) external {
        uint256 nonce = evc.getNonce(bytes19(bytes20(signer)), 0);
        evc.permit(signer, address(this), 0, nonce, block.timestamp, 0, data, "");
    }
}

contract EVCUtilSignatureCheckTest is Test {
    EthereumVaultConnectorHarness internal evc;
    ERC1271Client internal client;
    NestedPermitCaller internal caller;
    address internal account;
    address internal collateral;

    function setUp() public {
        evc = new EthereumVaultConnectorHarness();
        account = makeAddr("account");
        collateral = makeAddr("collateral");
        client = new ERC1271Client(address(evc), account);
        caller = new NestedPermitCaller(evc);

        vm.prank(account);
        evc.enableController(account, address(client));
    }

    function test_isValidSignature_calledByEVC_reverts(bytes32 hash, bytes calldata signature) external {
        evc.setOnBehalfOfAccount(account);

        for (uint8 i = 1; i <= uint8(type(ERC1271Client.Authentication).max); ++i) {
            client.setAuthentication(ERC1271Client.Authentication(i));

            vm.prank(address(evc));
            vm.expectRevert(EVCUtil.NotAuthorized.selector);
            IERC1271(address(client)).isValidSignature(hash, signature);
        }
    }

    /// @dev The check also rejects `isValidSignature` as the target of an EVC call whose account is authenticated.
    function test_isValidSignature_calledThroughEVC_reverts(bytes32 hash, bytes calldata signature) external {
        for (uint8 i = 1; i <= uint8(type(ERC1271Client.Authentication).max); ++i) {
            client.setAuthentication(ERC1271Client.Authentication(i));

            vm.prank(account);
            vm.expectRevert(EVCUtil.NotAuthorized.selector);
            evc.call(address(client), account, 0, abi.encodeCall(IERC1271.isValidSignature, (hash, signature)));
        }
    }

    function test_isValidSignature_notCalledByEVC_returnsMsgSender(bytes32 hash, bytes calldata signature) external {
        for (uint8 i = 1; i <= uint8(type(ERC1271Client.Authentication).max); ++i) {
            client.setAuthentication(ERC1271Client.Authentication(i));

            vm.prank(account);
            assertEq(IERC1271(address(client)).isValidSignature(hash, signature), IERC1271.isValidSignature.selector);
        }
    }

    function test_otherSelector_calledThroughEVC_returnsOnBehalfOfAccount(bytes4 selector) external {
        vm.assume(
            selector != IERC1271.isValidSignature.selector && selector != ERC1271Client.setAuthentication.selector
                && selector != ERC1271Client.checkAccountStatus.selector && selector != EVCUtil.EVC.selector
        );

        for (uint8 i = 1; i <= uint8(type(ERC1271Client.Authentication).max); ++i) {
            client.setAuthentication(ERC1271Client.Authentication(i));

            vm.prank(account);
            bytes memory result = evc.call(address(client), account, 0, abi.encodeWithSelector(selector));
            assertEq(abi.decode(result, (bytes4)), IERC1271.isValidSignature.selector);
        }
    }

    function test_nestedPermit_withSignerAuthenticatingThroughEVC_reverts() external {
        for (uint8 i = 1; i <= uint8(type(ERC1271Client.Authentication).max); ++i) {
            client.setAuthentication(ERC1271Client.Authentication(i));

            vm.expectRevert(Errors.EVC_NotAuthorized.selector);
            caller.run(account, address(client), abi.encodeCall(IEVC.enableCollateral, (address(client), collateral)));
        }
    }

    function test_nestedPermit_withProxiedSigner_reverts() external {
        address signer = address(new ForwardingProxy(address(new ERC1271Signer(address(evc), account))));

        vm.expectRevert(Errors.EVC_NotAuthorized.selector);
        caller.run(account, signer, abi.encodeCall(IEVC.enableCollateral, (signer, collateral)));
    }

    /// @dev Control for the tests above: the same permit executes when the signer does not read the EVC context.
    function test_nestedPermit_withSignerIgnoringEVCContext_executes() external {
        caller.run(account, address(client), abi.encodeCall(IEVC.enableCollateral, (address(client), collateral)));

        assertTrue(evc.isCollateralEnabled(address(client), collateral));
    }

    /// @dev Shows the premise of the tests above: during the signature check the execution context holds the account
    /// chosen by the caller. A signer that reads the context without EVCUtil is not covered by the check.
    function test_nestedPermit_withSignerReadingContextDirectly_executes() external {
        address signer = address(new ContextReadingSigner(evc, account));

        caller.run(account, signer, abi.encodeCall(IEVC.enableCollateral, (signer, collateral)));

        assertTrue(evc.isCollateralEnabled(signer, collateral));
    }
}
