// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../../utils/CreditVaultProtocolHarnessed.sol";

contract CreditVaultProtocolHandler is CreditVaultProtocolHarnessed {
    using Set for SetStorage;

    function handlerBatch(BatchItem[] calldata items) public payable {
        super.batch(items);

        if (executionContext.batchDepth != BATCH_DEPTH__INIT) return;

        verifyStorage();
        verifyVaultStatusChecks();
        verifyAccountStatusChecks();
    }
}

contract CreditVaultProtocolNoRevert is CreditVaultProtocolHarnessed {
    using Set for SetStorage;

    function batchRevert(
        BatchItem[] calldata
    )
        public
        payable
        override
        nonReentrant
        returns (
            BatchItemResult[] memory batchItemsResult,
            BatchItemResult[] memory accountsStatusResult,
            BatchItemResult[] memory vaultsStatusResult
        )
    {
        // doesn't rever as expected
        return (batchItemsResult, accountsStatusResult, vaultsStatusResult);
    }
}

contract BatchTest is Test {
    CreditVaultProtocolHandler internal cvp;

    function setUp() public {
        cvp = new CreditVaultProtocolHandler();
    }

    function test_Batch(address alice, address bob, uint seed) external {
        vm.assume(!cvp.haveCommonOwner(alice, bob));
        vm.assume(seed >= 3);

        ICVP.BatchItem[] memory items = new ICVP.BatchItem[](6);
        address controller = address(new Vault(cvp));
        address otherVault = address(new Vault(cvp));
        address alicesSubAccount = address(uint160(alice) ^ 0x10);

        vm.assume(bob != controller);

        // -------------- FIRST BATCH -------------------------
        items[0].allowError = false;
        items[0].onBehalfOfAccount = address(0);
        items[0].targetContract = address(cvp);
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(
            cvp.enableController.selector,
            alice,
            controller
        );

        items[1].allowError = false;
        items[1].onBehalfOfAccount = alice;
        items[1].targetContract = address(cvp);
        items[1].value = 0;
        items[1].data = abi.encodeWithSelector(
            cvp.setAccountOperator.selector,
            alice,
            bob,
            true
        );

        items[2].allowError = false;
        items[2].onBehalfOfAccount = alicesSubAccount;
        items[2].targetContract = otherVault;
        items[2].value = 0;
        items[2].data = abi.encodeWithSelector(
            Vault.requireChecks.selector,
            alicesSubAccount
        );

        items[3].allowError = false;
        items[3].onBehalfOfAccount = address(0);
        items[3].targetContract = controller;
        items[3].value = seed / 3;
        items[3].data = abi.encodeWithSelector(
            Vault.call.selector,
            otherVault,
            abi.encodeWithSelector(
                Target.callTest.selector,
                address(cvp),
                controller,
                seed / 3,
                true,
                alice
            )
        );

        items[4].allowError = false;
        items[4].onBehalfOfAccount = alice;
        items[4].targetContract = otherVault;
        items[4].value = type(uint).max;
        items[4].data = abi.encodeWithSelector(
            Target.callTest.selector,
            address(cvp),
            address(cvp),
            seed - seed / 3,
            true,
            alice
        );

        items[5].allowError = false;
        items[5].onBehalfOfAccount = alicesSubAccount;
        items[5].targetContract = address(cvp);
        items[5].value = 0;
        items[5].data = abi.encodeWithSelector(
            cvp.enableController.selector,
            alicesSubAccount,
            controller
        );

        hoax(alice, seed);
        cvp.handlerBatch{value: seed}(items);

        assertTrue(cvp.isControllerEnabled(alice, controller));
        assertTrue(cvp.isControllerEnabled(alicesSubAccount, controller));
        assertTrue(cvp.accountOperators(alice, bob));
        assertEq(address(otherVault).balance, seed);

        cvp.reset();
        Vault(controller).reset();
        Vault(otherVault).reset();

        // -------------- SECOND BATCH -------------------------
        items = new ICVP.BatchItem[](1);

        items[0].allowError = false;
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = address(cvp);
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(
            cvp.call.selector,
            address(cvp),
            alice,
            ""
        );

        vm.prank(bob);
        vm.expectRevert(CreditVaultProtocol.CVP_InvalidAddress.selector);
        cvp.handlerBatch(items);

        // -------------- THIRD BATCH -------------------------
        items = new ICVP.BatchItem[](1);

        items[0].allowError = true;
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = address(cvp);
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(
            cvp.call.selector,
            address(cvp),
            alice,
            ""
        );

        // no revert this time because error is allowed
        vm.prank(bob);
        cvp.handlerBatch(items);

        cvp.reset();
        Vault(controller).reset();
        Vault(otherVault).reset();

        // -------------- FOURTH BATCH -------------------------
        items = new ICVP.BatchItem[](3);

        items[0].allowError = false;
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = controller;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(
            Vault.disableController.selector,
            alice
        );

        items[1].allowError = false;
        items[1].onBehalfOfAccount = address(0);
        items[1].targetContract = controller;
        items[1].value = 0;
        items[1].data = abi.encodeWithSelector(
            Vault.requireChecks.selector,
            bob
        );

        items[2].allowError = false;
        items[2].onBehalfOfAccount = bob;
        items[2].targetContract = otherVault;
        items[2].value = 0;
        items[2].data = abi.encodeWithSelector(
            Vault.requireChecks.selector,
            alicesSubAccount
        );

        vm.prank(bob);
        cvp.handlerBatch(items);
        assertFalse(cvp.isControllerEnabled(alice, controller));

        // -------------- FIFTH BATCH -------------------------
        items = new ICVP.BatchItem[](1);

        items[0].allowError = false;
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = otherVault;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(Target.revertEmptyTest.selector);

        vm.prank(alice);
        vm.expectRevert(bytes("CVP-empty-error"));
        cvp.handlerBatch(items);
    }

    function test_RevertIfDeferralDepthExceeded_Batch_BatchRevert(
        address alice,
        uint seed
    ) external {
        address vault = address(new Vault(cvp));

        ICVP.BatchItem[] memory items = new ICVP.BatchItem[](9);

        for (int i = int(items.length - 1); i >= 0; --i) {
            uint j = uint(i);
            items[j].allowError = false;
            items[j].onBehalfOfAccount = alice;
            items[j].targetContract = address(cvp);
            items[j].value = 0;

            if (j == items.length - 1) {
                ICVP.BatchItem[] memory nestedItems = new ICVP.BatchItem[](2);

                nestedItems[0].allowError = false;
                nestedItems[0].onBehalfOfAccount = address(0);
                nestedItems[0].targetContract = vault;
                nestedItems[0].value = 0;
                nestedItems[0].data = abi.encodeWithSelector(
                    Vault.requireChecks.selector,
                    alice
                );

                nestedItems[1].allowError = false;
                nestedItems[1].onBehalfOfAccount = address(0);
                nestedItems[1].targetContract = address(cvp);
                nestedItems[1].value = 0;
                nestedItems[1].data = abi.encodeWithSelector(
                    cvp.enableController.selector,
                    alice,
                    vault
                );

                items[j].data = abi.encodeWithSelector(
                    seed % 2 == 0
                        ? cvp.batch.selector
                        : cvp.batchRevert.selector,
                    nestedItems
                );
            } else {
                ICVP.BatchItem[] memory nestedItems = new ICVP.BatchItem[](1);
                nestedItems[0] = items[j + 1];

                items[j].data = abi.encodeWithSelector(
                    cvp.batch.selector,
                    nestedItems
                );
            }
        }

        vm.prank(alice);
        vm.expectRevert(CreditVaultProtocol.CVP_BatchDepthViolation.selector);
        cvp.handlerBatch(items);

        // check one item less call only if the most nested batch call doesn't go through
        // the batchRevert() function. if it does, we'll revert with a standard
        // CVP_RevertedBatchResult error
        if (seed % 2 != 0) return;

        // should succeed when one less item. doesn't revert anymore,
        // but checks are performed only once, when the top level batch concludes
        ICVP.BatchItem[] memory itemsOneLess = new ICVP.BatchItem[](8);
        for (uint i = 1; i <= itemsOneLess.length; ++i) {
            itemsOneLess[i - 1] = items[i];
        }

        vm.prank(alice);
        cvp.handlerBatch(itemsOneLess);
    }

    // for coverage
    function test_RevertIfDeferralDepthExceeded_BatchSimulation(
        address alice
    ) external {
        ICVP.BatchItem[] memory items = new ICVP.BatchItem[](1);

        items[0].allowError = false;
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = address(0);
        items[0].value = 0;
        items[0].data = "";

        cvp.setBatchDepth(9);

        vm.prank(alice);
        vm.expectRevert(CreditVaultProtocol.CVP_BatchDepthViolation.selector);
        cvp.batchSimulation(items);
    }

    function test_RevertIfChecksReentrancy_Batch(address alice) external {
        address vault = address(new VaultMalicious(cvp));

        ICVP.BatchItem[] memory items = new ICVP.BatchItem[](1);
        items[0].allowError = false;
        items[0].onBehalfOfAccount = address(0);
        items[0].targetContract = vault;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(
            Vault.requireChecks.selector,
            alice
        );

        // internal batch in the malicious vault reverts with CVP_ChecksReentrancy error,
        // check VaultMalicious implementation
        VaultMalicious(vault).setFunctionSelectorToCall(ICVP.batch.selector);
        VaultMalicious(vault).setExpectedErrorSelector(
            CreditVaultProtocol.CVP_ChecksReentrancy.selector
        );

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultProtocol.CVP_VaultStatusViolation.selector,
                vault,
                "malicious vault"
            )
        );
        cvp.batch(items);
    }

    function test_RevertIfChecksReentrancy_BatchRevert_BatchSimulation(
        address alice
    ) external {
        address vault = address(new VaultMalicious(cvp));

        ICVP.BatchItem[] memory items = new ICVP.BatchItem[](1);
        items[0].allowError = false;
        items[0].onBehalfOfAccount = address(0);
        items[0].targetContract = vault;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(
            Vault.requireChecks.selector,
            alice
        );

        // internal batch in the malicious vault reverts with CVP_ChecksReentrancy error,
        // check VaultMalicious implementation
        // error will be encoded in the result
        ICVP.BatchItemResult[]
            memory expectedBatchItemsResult = new ICVP.BatchItemResult[](1);
        ICVP.BatchItemResult[]
            memory expectedAccountsStatusResult = new ICVP.BatchItemResult[](1);
        ICVP.BatchItemResult[]
            memory expectedVaultsStatusResult = new ICVP.BatchItemResult[](1);

        expectedBatchItemsResult[0].success = true;
        expectedBatchItemsResult[0].result = "";

        expectedAccountsStatusResult[0].success = true;
        expectedAccountsStatusResult[0].result = "";

        expectedVaultsStatusResult[0].success = false;
        expectedVaultsStatusResult[0].result = abi.encodeWithSelector(
            CreditVaultProtocol.CVP_VaultStatusViolation.selector,
            vault,
            "malicious vault"
        );

        VaultMalicious(vault).setFunctionSelectorToCall(
            ICVP.batchRevert.selector
        );
        VaultMalicious(vault).setExpectedErrorSelector(
            CreditVaultProtocol.CVP_ChecksReentrancy.selector
        );

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultProtocol.CVP_RevertedBatchResult.selector,
                expectedBatchItemsResult,
                expectedAccountsStatusResult,
                expectedVaultsStatusResult
            )
        );
        cvp.batchRevert(items);

        // same should happen for batchSimulation() but without reverting with standard error
        VaultMalicious(vault).setFunctionSelectorToCall(
            ICVP.batchRevert.selector
        );
        VaultMalicious(vault).setExpectedErrorSelector(
            CreditVaultProtocol.CVP_ChecksReentrancy.selector
        );

        vm.prank(alice);
        (
            ICVP.BatchItemResult[] memory batchItemsResult,
            ICVP.BatchItemResult[] memory accountsStatusResult,
            ICVP.BatchItemResult[] memory vaultsStatusResult
        ) = cvp.batchSimulation(items);

        assertEq(batchItemsResult.length, 1);
        assertEq(
            batchItemsResult[0].success,
            expectedBatchItemsResult[0].success
        );
        assertEq(
            batchItemsResult[0].result,
            expectedBatchItemsResult[0].result
        );

        assertEq(accountsStatusResult.length, 1);
        assertEq(
            accountsStatusResult[0].success,
            expectedAccountsStatusResult[0].success
        );
        assertEq(
            accountsStatusResult[0].result,
            expectedAccountsStatusResult[0].result
        );

        assertEq(vaultsStatusResult.length, 1);
        assertEq(
            vaultsStatusResult[0].success,
            expectedVaultsStatusResult[0].success
        );
        assertEq(
            vaultsStatusResult[0].result,
            expectedVaultsStatusResult[0].result
        );
    }

    function test_RevertIfImpersonateReentrancy_Batch(address alice) external {
        vm.assume(alice != address(0));

        address controller = address(new Vault(cvp));
        address collateral = address(new VaultMalicious(cvp));

        vm.prank(alice);
        cvp.enableController(alice, controller);

        vm.prank(alice);
        cvp.enableCollateral(alice, collateral);

        // internal batch in the malicious vault reverts with CVP_ImpersonateReentancy error,
        // check VaultMalicious implementation
        VaultMalicious(collateral).setFunctionSelectorToCall(
            ICVP.batch.selector
        );
        VaultMalicious(collateral).setExpectedErrorSelector(
            CreditVaultProtocol.CVP_ImpersonateReentancy.selector
        );

        vm.prank(controller);
        (bool success, bytes memory result) = cvp.impersonate(
            collateral,
            alice,
            abi.encodeWithSelector(Vault.requireChecks.selector, alice)
        );

        assertFalse(success);
        assertEq(
            result,
            abi.encodeWithSelector(
                CreditVaultProtocol.CVP_VaultStatusViolation.selector,
                collateral,
                "malicious vault"
            )
        );
    }

    function test_RevertIfImpersonateReentrancy_BatchRevert_BatchSimulation(
        address alice
    ) external {
        vm.assume(alice != address(0));

        address controller = address(new Vault(cvp));
        address collateral = address(new VaultMalicious(cvp));

        vm.prank(alice);
        cvp.enableController(alice, controller);

        vm.prank(alice);
        cvp.enableCollateral(alice, collateral);

        // internal batch in the malicious vault reverts with CVP_ImpersonateReentancy error,
        // check VaultMalicious implementation
        VaultMalicious(collateral).setFunctionSelectorToCall(
            ICVP.batchRevert.selector
        );
        VaultMalicious(collateral).setExpectedErrorSelector(
            CreditVaultProtocol.CVP_ImpersonateReentancy.selector
        );

        vm.prank(controller);
        (bool success, bytes memory result) = cvp.impersonate(
            collateral,
            alice,
            abi.encodeWithSelector(Vault.requireChecks.selector, alice)
        );
        assertFalse(success);
        assertEq(
            result,
            abi.encodeWithSelector(
                CreditVaultProtocol.CVP_VaultStatusViolation.selector,
                collateral,
                "malicious vault"
            )
        );
    }

    function test_BatchRevert_BatchSimulation(address alice) external {
        ICVP.BatchItem[] memory items = new ICVP.BatchItem[](1);
        ICVP.BatchItemResult[]
            memory expectedBatchItemsResult = new ICVP.BatchItemResult[](1);
        ICVP.BatchItemResult[]
            memory expectedAccountsStatusResult = new ICVP.BatchItemResult[](1);
        ICVP.BatchItemResult[]
            memory expectedVaultsStatusResult = new ICVP.BatchItemResult[](1);

        address controller = address(new Vault(cvp));

        vm.prank(alice);
        cvp.enableController(alice, controller);

        items[0].allowError = false;
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = controller;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(
            Vault.requireChecks.selector,
            alice
        );

        expectedBatchItemsResult[0].success = true;
        expectedBatchItemsResult[0].result = "";

        expectedAccountsStatusResult[0].success = true;
        expectedAccountsStatusResult[0].result = "";

        expectedVaultsStatusResult[0].success = true;
        expectedVaultsStatusResult[0].result = "";

        // regular batch doesn't revert
        vm.prank(alice);
        cvp.batch(items);

        {
            vm.prank(alice);
            try cvp.batchRevert(items) {
                assert(false);
            } catch (bytes memory err) {
                assertEq(
                    bytes4(err),
                    CreditVaultProtocol.CVP_RevertedBatchResult.selector
                );

                assembly {
                    err := add(err, 4)
                }
                (
                    ICVP.BatchItemResult[] memory batchItemsResult,
                    ICVP.BatchItemResult[] memory accountsStatusResult,
                    ICVP.BatchItemResult[] memory vaultsStatusResult
                ) = abi.decode(
                        err,
                        (
                            ICVP.BatchItemResult[],
                            ICVP.BatchItemResult[],
                            ICVP.BatchItemResult[]
                        )
                    );

                assertEq(
                    expectedBatchItemsResult.length,
                    batchItemsResult.length
                );
                assertEq(
                    expectedBatchItemsResult[0].success,
                    batchItemsResult[0].success
                );
                assertEq(
                    keccak256(expectedBatchItemsResult[0].result),
                    keccak256(batchItemsResult[0].result)
                );

                assertEq(
                    expectedAccountsStatusResult.length,
                    accountsStatusResult.length
                );
                assertEq(
                    expectedAccountsStatusResult[0].success,
                    accountsStatusResult[0].success
                );
                assertEq(
                    keccak256(expectedAccountsStatusResult[0].result),
                    keccak256(accountsStatusResult[0].result)
                );

                assertEq(
                    expectedVaultsStatusResult.length,
                    vaultsStatusResult.length
                );
                assertEq(
                    expectedVaultsStatusResult[0].success,
                    vaultsStatusResult[0].success
                );
                assertEq(
                    keccak256(expectedVaultsStatusResult[0].result),
                    keccak256(vaultsStatusResult[0].result)
                );
            }
        }

        {
            vm.prank(alice);
            (
                ICVP.BatchItemResult[] memory batchItemsResult,
                ICVP.BatchItemResult[] memory accountsStatusResult,
                ICVP.BatchItemResult[] memory vaultsStatusResult
            ) = cvp.batchSimulation(items);

            assertEq(expectedBatchItemsResult.length, batchItemsResult.length);
            assertEq(
                expectedBatchItemsResult[0].success,
                batchItemsResult[0].success
            );
            assertEq(
                keccak256(expectedBatchItemsResult[0].result),
                keccak256(batchItemsResult[0].result)
            );

            assertEq(
                expectedAccountsStatusResult.length,
                accountsStatusResult.length
            );
            assertEq(
                expectedAccountsStatusResult[0].success,
                accountsStatusResult[0].success
            );
            assertEq(
                keccak256(expectedAccountsStatusResult[0].result),
                keccak256(accountsStatusResult[0].result)
            );

            assertEq(
                expectedVaultsStatusResult.length,
                vaultsStatusResult.length
            );
            assertEq(
                expectedVaultsStatusResult[0].success,
                vaultsStatusResult[0].success
            );
            assertEq(
                keccak256(expectedVaultsStatusResult[0].result),
                keccak256(vaultsStatusResult[0].result)
            );
        }

        // invalidate both checks
        Vault(controller).setVaultStatusState(1);
        Vault(controller).setAccountStatusState(1);

        // update expected behavior
        expectedAccountsStatusResult[0].success = false;
        expectedAccountsStatusResult[0].result = abi.encodeWithSelector(
            CreditVaultProtocol.CVP_AccountStatusViolation.selector,
            alice,
            "account status violation"
        );

        expectedVaultsStatusResult[0].success = false;
        expectedVaultsStatusResult[0].result = abi.encodeWithSelector(
            CreditVaultProtocol.CVP_VaultStatusViolation.selector,
            controller,
            "vault status violation"
        );

        // regular batch reverts now
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultProtocol.CVP_AccountStatusViolation.selector,
                alice,
                "account status violation"
            )
        );
        cvp.batch(items);

        {
            vm.prank(alice);
            try cvp.batchRevert(items) {
                assert(false);
            } catch (bytes memory err) {
                assertEq(
                    bytes4(err),
                    CreditVaultProtocol.CVP_RevertedBatchResult.selector
                );

                assembly {
                    err := add(err, 4)
                }
                (
                    ICVP.BatchItemResult[] memory batchItemsResult,
                    ICVP.BatchItemResult[] memory accountsStatusResult,
                    ICVP.BatchItemResult[] memory vaultsStatusResult
                ) = abi.decode(
                        err,
                        (
                            ICVP.BatchItemResult[],
                            ICVP.BatchItemResult[],
                            ICVP.BatchItemResult[]
                        )
                    );

                assertEq(
                    expectedBatchItemsResult.length,
                    batchItemsResult.length
                );
                assertEq(
                    expectedBatchItemsResult[0].success,
                    batchItemsResult[0].success
                );
                assertEq(
                    keccak256(expectedBatchItemsResult[0].result),
                    keccak256(batchItemsResult[0].result)
                );

                assertEq(
                    expectedAccountsStatusResult.length,
                    accountsStatusResult.length
                );
                assertEq(
                    expectedAccountsStatusResult[0].success,
                    accountsStatusResult[0].success
                );
                assertEq(
                    keccak256(expectedAccountsStatusResult[0].result),
                    keccak256(accountsStatusResult[0].result)
                );

                assertEq(
                    expectedVaultsStatusResult.length,
                    vaultsStatusResult.length
                );
                assertEq(
                    expectedVaultsStatusResult[0].success,
                    vaultsStatusResult[0].success
                );
                assertEq(
                    keccak256(expectedVaultsStatusResult[0].result),
                    keccak256(vaultsStatusResult[0].result)
                );
            }
        }

        {
            vm.prank(alice);
            (
                ICVP.BatchItemResult[] memory batchItemsResult,
                ICVP.BatchItemResult[] memory accountsStatusResult,
                ICVP.BatchItemResult[] memory vaultsStatusResult
            ) = cvp.batchSimulation(items);

            assertEq(expectedBatchItemsResult.length, batchItemsResult.length);
            assertEq(
                expectedBatchItemsResult[0].success,
                batchItemsResult[0].success
            );
            assertEq(
                keccak256(expectedBatchItemsResult[0].result),
                keccak256(batchItemsResult[0].result)
            );

            assertEq(
                expectedAccountsStatusResult.length,
                accountsStatusResult.length
            );
            assertEq(
                expectedAccountsStatusResult[0].success,
                accountsStatusResult[0].success
            );
            assertEq(
                keccak256(expectedAccountsStatusResult[0].result),
                keccak256(accountsStatusResult[0].result)
            );

            assertEq(
                expectedVaultsStatusResult.length,
                vaultsStatusResult.length
            );
            assertEq(
                expectedVaultsStatusResult[0].success,
                vaultsStatusResult[0].success
            );
            assertEq(
                keccak256(expectedVaultsStatusResult[0].result),
                keccak256(vaultsStatusResult[0].result)
            );
        }
    }

    function test_RevertIfBatchRevertDoesntRevert_BatchSimulation(
        address alice
    ) external {
        ICVP cvp_noRevert = new CreditVaultProtocolNoRevert();
        vm.prank(alice);
        vm.expectRevert(CreditVaultProtocol.CVP_BatchPanic.selector);
        cvp_noRevert.batchSimulation(new ICVP.BatchItem[](0));
    }
}
