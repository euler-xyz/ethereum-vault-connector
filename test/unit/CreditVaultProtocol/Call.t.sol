// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../../utils/CreditVaultProtocolHarnessed.sol";

contract CreditVaultProtocolHandler is CreditVaultProtocolHarnessed {
    using Set for SetStorage;

    function handlerCall(address targetContract, address onBehalfOfAccount, bytes calldata data) public payable 
    returns (bool success, bytes memory result) {
        (success, result) = super.call(targetContract, onBehalfOfAccount, data);

        verifyStorage();
    }
}

contract CallTest is Test {
    CreditVaultProtocolHandler internal cvp;

    function setUp() public {
        cvp = new CreditVaultProtocolHandler();
    }

    function test_Call(address alice, uint96 seed) public {
        address account;
        if (seed % 2 == 0) {
            // in this case the account is not alice's sub-account thus alice must be an operator
            account = address(uint160(uint160(alice) ^ 256));
            vm.prank(account);
            cvp.setAccountOperator(account, alice, true);
        } else {
            // in this case the account is alice's sub-account
            account = address(uint160(uint160(alice) ^ (seed % 256)));
        }
        vm.assume(account != address(0));

        address targetContract = address(new Target());
        vm.assume(targetContract != address(cvp));

        bytes memory data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector,
            address(cvp),
            address(cvp),
            seed,
            false,
            account
        );

        hoax(alice, seed);
        (bool success, bytes memory result) = cvp.handlerCall{value: seed}(
            targetContract,
            account,
            data
        );

        assertTrue(success);
        assertEq(abi.decode(result, (uint)), seed);

        // if called from a batch, the ETH value does not get forwarded
        data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector,
            address(cvp),
            address(cvp),
            0,  // we're expecting ETH not to get forwarded
            true,
            account
        );

        ICVP.BatchItem[] memory items = new ICVP.BatchItem[](1);

        items[0].allowError = false;
        items[0].onBehalfOfAccount = address(0);
        items[0].targetContract = address(cvp);
        items[0].msgValue = seed;    // this value will get ignored
        items[0].data = abi.encodeWithSelector(
            cvp.call.selector,
            targetContract,
            account,
            data
        );

        hoax(alice, seed);
        cvp.batch(items);

        // should also succeed if the onBehalfOfAccount address passed is 0. it should be replaced with msg.sender
        data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector,
            address(cvp),
            address(cvp),
            seed,
            false,
            alice
        );

        hoax(alice, seed);
        (success, result) = cvp.handlerCall{value: seed}(
            targetContract,
            address(0),
            data
        );

        assertTrue(success);
        assertEq(abi.decode(result, (uint)), seed);
    }

    function test_RevertIfNotOwnerOrOperator_Call(address alice, address bob, uint seed) public {
        vm.assume(!cvp.haveCommonOwner(alice, bob));
        vm.assume(bob != address(0));
        
        address targetContract = address(new Target());
        vm.assume(targetContract != address(cvp));

        bytes memory data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector,
            address(cvp),
            address(cvp),
            seed,
            false,
            alice
        );

        hoax(alice, seed);
        vm.expectRevert(CreditVaultProtocol.CVP_NotAuthorized.selector);
        (bool success,) = cvp.handlerCall{value: seed}(
            targetContract,
            bob,
            data
        );

        assertFalse(success);
    }


    function test_RevertIfTargetContractInvalid_Call(address alice, uint seed) public {
        vm.assume(alice != address(0));

        // target contract is the CVP
        address targetContract = address(cvp);

        bytes memory data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector,
            address(cvp),
            targetContract,
            seed,
            false,
            alice
        );

        hoax(alice, seed);
        vm.expectRevert(CreditVaultProtocol.CVP_InvalidAddress.selector);

        (bool success,) = cvp.handlerCall{value: seed}(
            targetContract,
            alice,
            data
        );

        assertFalse(success);

        // target contract is the ERC1820 registry
        targetContract = 0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24;
        address dummyTarget = address(new Target());

        vm.etch(targetContract, dummyTarget.code);

        data = abi.encodeWithSelector(
            Target(targetContract).callTest.selector,
            address(cvp),
            targetContract,
            seed,
            false,
            alice
        );

        hoax(alice, seed);
        vm.expectRevert(CreditVaultProtocol.CVP_InvalidAddress.selector);

        (success,) = cvp.handlerCall{value: seed}(
            targetContract,
            alice,
            data
        );

        assertFalse(success);
    }
}
