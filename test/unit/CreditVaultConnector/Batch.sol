// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../cvc/CreditVaultConnectorHarness.sol";

contract CreditVaultConnectorHandler is CreditVaultConnectorHarness {
    using ExecutionContext for EC;
    using Set for SetStorage;

    function handlerBatch(BatchItem[] calldata items) public payable {
        super.batch(items);

        verifyVaultStatusChecks();
        verifyAccountStatusChecks();
    }
}

contract CreditVaultConnectorNoRevert is CreditVaultConnectorHarness {
    using Set for SetStorage;

    function batchRevert(
        BatchItem[] calldata
    ) public payable override nonReentrant {
        // doesn't revert as expected
        return;
    }
}

contract BatchTest is Test {
    CreditVaultConnectorHandler internal cvc;

    event CallWithContext(
        address indexed caller,
        address indexed targetContract,
        address indexed onBehalfOfAccount,
        bytes4 selector
    );

    function setUp() public {
        cvc = new CreditVaultConnectorHandler();
    }

    function test_Batch(address alice, address bob, uint seed) external {
        vm.assume(
            alice != address(0) && alice != address(cvc) && bob != address(cvc)
        );
        vm.assume(bob != address(0) && !cvc.haveCommonOwner(alice, bob));
        vm.assume(seed >= 4);

        ICVC.BatchItem[] memory items = new ICVC.BatchItem[](6);
        address controller = address(new Vault(cvc));
        address otherVault = address(new Vault(cvc));
        address alicesSubAccount = address(uint160(alice) ^ 0x10);

        vm.assume(bob != controller);

        // -------------- FIRST BATCH -------------------------
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = address(cvc);
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(
            cvc.enableController.selector,
            alice,
            controller
        );

        items[1].onBehalfOfAccount = alice;
        items[1].targetContract = address(cvc);
        items[1].value = 0;
        items[1].data = abi.encodeWithSelector(
            cvc.setAccountOperator.selector,
            alice,
            bob,
            true
        );

        items[2].onBehalfOfAccount = alicesSubAccount;
        items[2].targetContract = otherVault;
        items[2].value = 0;
        items[2].data = abi.encodeWithSelector(
            Vault.requireChecks.selector,
            alicesSubAccount
        );

        items[3].onBehalfOfAccount = alice;
        items[3].targetContract = controller;
        items[3].value = seed / 3;
        items[3].data = abi.encodeWithSelector(
            Vault.call.selector,
            otherVault,
            abi.encodeWithSelector(
                Target.callTest.selector,
                address(cvc),
                controller,
                seed / 3,
                alice,
                false
            )
        );

        items[4].onBehalfOfAccount = alice;
        items[4].targetContract = otherVault;
        items[4].value = type(uint).max;
        items[4].data = abi.encodeWithSelector(
            Target.callTest.selector,
            address(cvc),
            address(cvc),
            seed - seed / 3,
            alice,
            false
        );

        items[5].onBehalfOfAccount = alicesSubAccount;
        items[5].targetContract = address(cvc);
        items[5].value = 0;
        items[5].data = abi.encodeWithSelector(
            cvc.enableController.selector,
            alicesSubAccount,
            controller
        );

        vm.deal(alice, seed);
        vm.expectEmit(true, true, true, true, address(cvc));
        emit CallWithContext(
            alice,
            otherVault,
            alicesSubAccount,
            Vault.requireChecks.selector
        );
        vm.expectEmit(true, true, true, true, address(cvc));
        emit CallWithContext(alice, controller, alice, Vault.call.selector);
        vm.expectEmit(true, true, true, true, address(cvc));
        emit CallWithContext(
            alice,
            otherVault,
            alice,
            Target.callTest.selector
        );
        vm.prank(alice);
        cvc.handlerBatch{value: seed}(items);

        assertTrue(cvc.isControllerEnabled(alice, controller));
        assertTrue(cvc.isControllerEnabled(alicesSubAccount, controller));
        assertEq(cvc.isAccountOperatorAuthorized(alice, bob), true);
        assertEq(address(otherVault).balance, seed);

        cvc.reset();
        Vault(controller).reset();
        Vault(otherVault).reset();

        // -------------- SECOND BATCH -------------------------
        items = new ICVC.BatchItem[](1);

        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = address(cvc);
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(
            cvc.call.selector,
            address(cvc),
            alice,
            0,
            ""
        );

        vm.prank(bob);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidAddress.selector);
        cvc.handlerBatch(items);

        // -------------- THIRD BATCH -------------------------
        items = new ICVC.BatchItem[](4);

        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = controller;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(
            Vault.disableController.selector,
            alice
        );

        items[1].onBehalfOfAccount = bob;
        items[1].targetContract = controller;
        items[1].value = 0;
        items[1].data = abi.encodeWithSelector(
            Vault.requireChecks.selector,
            bob
        );

        items[2].onBehalfOfAccount = bob;
        items[2].targetContract = otherVault;
        items[2].value = 0;
        items[2].data = abi.encodeWithSelector(
            Vault.requireChecks.selector,
            alicesSubAccount
        );

        items[3].onBehalfOfAccount = alice;
        items[3].targetContract = otherVault;
        items[3].value = 0;
        items[3].data = abi.encodeWithSelector(
            Target.callTest.selector,
            address(cvc),
            address(cvc),
            0,
            alice,
            true
        );

        vm.prank(bob);
        vm.expectEmit(true, true, true, true, address(cvc));
        emit CallWithContext(
            bob,
            controller,
            alice,
            Vault.disableController.selector
        );
        vm.expectEmit(true, true, true, true, address(cvc));
        emit CallWithContext(
            bob,
            controller,
            bob,
            Vault.requireChecks.selector
        );
        vm.expectEmit(true, true, true, true, address(cvc));
        emit CallWithContext(
            bob,
            otherVault,
            bob,
            Vault.requireChecks.selector
        );
        vm.expectEmit(true, true, true, true, address(cvc));
        emit CallWithContext(bob, otherVault, alice, Target.callTest.selector);
        cvc.handlerBatch(items);
        assertFalse(cvc.isControllerEnabled(alice, controller));

        // -------------- FOURTH BATCH -------------------------
        items = new ICVC.BatchItem[](1);

        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = otherVault;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(Target.revertEmptyTest.selector);

        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_EmptyError.selector);
        cvc.handlerBatch(items);
    }

    function test_RevertIfDepthExceeded_Batch(address alice) external {
        vm.assume(alice != address(0) && alice != address(cvc));
        address vault = address(new Vault(cvc));

        ICVC.BatchItem[] memory items = new ICVC.BatchItem[](10);

        for (int i = int(items.length - 1); i >= 0; --i) {
            uint j = uint(i);
            items[j].onBehalfOfAccount = alice;
            items[j].targetContract = address(cvc);
            items[j].value = 0;

            if (j == items.length - 1) {
                ICVC.BatchItem[] memory nestedItems = new ICVC.BatchItem[](2);

                // non-checks-deferrable call
                nestedItems[0].onBehalfOfAccount = alice;
                nestedItems[0].targetContract = vault;
                nestedItems[0].value = 0;
                nestedItems[0].data = abi.encodeWithSelector(
                    Vault.requireChecks.selector,
                    alice
                );

                // non-checks-deferrable call
                nestedItems[1].onBehalfOfAccount = alice;
                nestedItems[1].targetContract = address(cvc);
                nestedItems[1].value = 0;
                nestedItems[1].data = abi.encodeWithSelector(
                    cvc.enableController.selector,
                    alice,
                    vault
                );

                items[j].data = abi.encodeWithSelector(
                    cvc.batch.selector,
                    nestedItems
                );
            } else {
                ICVC.BatchItem[] memory nestedItems = new ICVC.BatchItem[](1);
                nestedItems[0] = items[j + 1];

                items[j].data = abi.encodeWithSelector(
                    cvc.batch.selector,
                    nestedItems
                );
            }
        }

        vm.prank(alice);
        vm.expectRevert(ExecutionContext.CallDepthViolation.selector);
        cvc.batch(items);

        // should succeed when one less item. doesn't revert anymore,
        // but checks are performed only once, when the top level batch concludes
        ICVC.BatchItem[] memory itemsOneLess = new ICVC.BatchItem[](8);
        for (uint i = 1; i <= itemsOneLess.length; ++i) {
            itemsOneLess[i - 1] = items[i];
        }

        vm.prank(alice);
        cvc.batch(itemsOneLess);
    }

    // for coverage
    function test_RevertIfSimulationBatchNested_BatchRevert_BatchSimulation(
        address alice
    ) external {
        vm.assume(alice != address(cvc));

        ICVC.BatchItem[] memory items = new ICVC.BatchItem[](1);

        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = address(0);
        items[0].value = 0;
        items[0].data = "";

        cvc.setCallDepth(10);

        vm.prank(alice);
        vm.expectRevert(
            CreditVaultConnector.CVC_SimulationBatchNested.selector
        );
        cvc.batchRevert(items);

        vm.prank(alice);
        vm.expectRevert(
            CreditVaultConnector.CVC_SimulationBatchNested.selector
        );
        cvc.batchSimulation(items);
    }

    function test_RevertIfChecksReentrancy_AcquireChecksLock_Batch(
        address alice
    ) external {
        vm.assume(alice != address(cvc));
        cvc.setChecksLock(true);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            )
        );
        cvc.batch(new ICVC.BatchItem[](0));
        cvc.setChecksLock(false);

        address vault = address(new VaultMalicious(cvc));

        ICVC.BatchItem[] memory items = new ICVC.BatchItem[](1);
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = vault;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(
            Vault.requireChecksWithSimulationCheck.selector,
            alice,
            false
        );

        // internal batch in the malicious vault reverts with CVC_ChecksReentrancy error,
        // check VaultMalicious implementation
        VaultMalicious(vault).setExpectedErrorSelector(
            CreditVaultConnector.CVC_ChecksReentrancy.selector
        );

        vm.prank(alice);
        vm.expectRevert(bytes("malicious vault"));
        cvc.batch(items);
    }

    function test_RevertIfChecksReentrancy_AcquireChecksLock_BatchRevert_BatchSimulation(
        address alice
    ) external {
        vm.assume(alice != address(cvc));

        cvc.setChecksLock(true);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            )
        );
        cvc.batchRevert(new ICVC.BatchItem[](0));

        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_ChecksReentrancy.selector
            )
        );
        cvc.batchSimulation(new ICVC.BatchItem[](0));
        cvc.setChecksLock(false);

        address vault = address(new VaultMalicious(cvc));

        ICVC.BatchItem[] memory items = new ICVC.BatchItem[](1);
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = vault;
        items[0].value = 0;
        items[0].data = abi.encodeWithSelector(
            Vault.requireChecksWithSimulationCheck.selector,
            alice,
            true
        );

        // internal batch in the malicious vault reverts with CVC_ChecksReentrancy error,
        // check VaultMalicious implementation
        // error will be encoded in the result
        ICVC.BatchItemResult[]
            memory expectedBatchItemsResult = new ICVC.BatchItemResult[](1);
        ICVC.BatchItemResult[]
            memory expectedAccountsStatusResult = new ICVC.BatchItemResult[](1);
        ICVC.BatchItemResult[]
            memory expectedVaultsStatusResult = new ICVC.BatchItemResult[](1);

        expectedBatchItemsResult[0].success = true;
        expectedBatchItemsResult[0].result = "";

        expectedAccountsStatusResult[0].success = true;
        expectedAccountsStatusResult[0].result = "";

        expectedVaultsStatusResult[0].success = false;
        expectedVaultsStatusResult[0].result = abi.encodeWithSignature(
            "Error(string)",
            "malicious vault"
        );

        VaultMalicious(vault).setExpectedErrorSelector(
            CreditVaultConnector.CVC_ChecksReentrancy.selector
        );

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_RevertedBatchResult.selector,
                expectedBatchItemsResult,
                expectedAccountsStatusResult,
                expectedVaultsStatusResult
            )
        );
        cvc.batchRevert(items);

        // same should happen for batchSimulation() but without reverting with standard error
        VaultMalicious(vault).setExpectedErrorSelector(
            CreditVaultConnector.CVC_ChecksReentrancy.selector
        );

        vm.prank(alice);
        (
            ICVC.BatchItemResult[] memory batchItemsResult,
            ICVC.BatchItemResult[] memory accountsStatusResult,
            ICVC.BatchItemResult[] memory vaultsStatusResult
        ) = cvc.batchSimulation(items);

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

    function test_RevertIfImpersonateReentrancy_AcquireImpersonateLock_Batch(
        address alice
    ) external {
        vm.assume(alice != address(0) && alice != address(cvc));

        cvc.setImpersonateLock(true);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_ImpersonateReentrancy.selector
            )
        );
        cvc.batch(new ICVC.BatchItem[](0));
        cvc.setImpersonateLock(false);

        address controller = address(new Vault(cvc));
        address collateral = address(new VaultMalicious(cvc));

        vm.prank(alice);
        cvc.enableController(alice, controller);

        vm.prank(alice);
        cvc.enableCollateral(alice, collateral);

        // internal batch in the malicious vault reverts with CVC_ImpersonateReentrancy error,
        // check VaultMalicious implementation
        VaultMalicious(collateral).setExpectedErrorSelector(
            CreditVaultConnector.CVC_ImpersonateReentrancy.selector
        );

        vm.prank(controller);
        vm.expectRevert("callBatch/expected-error");
        cvc.impersonate(
            collateral,
            alice,
            0,
            abi.encodeWithSelector(VaultMalicious.callBatch.selector)
        );
    }

    function test_RevertIfImpersonateReentrancy_AcquireImpersonateLock_BatchRevert_BatchSimulation(
        address alice
    ) external {
        vm.assume(alice != address(0) && alice != address(cvc));

        cvc.setImpersonateLock(true);
        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_ImpersonateReentrancy.selector
            )
        );
        cvc.batchRevert(new ICVC.BatchItem[](0));

        vm.expectRevert(
            abi.encodeWithSelector(
                CreditVaultConnector.CVC_ImpersonateReentrancy.selector
            )
        );
        cvc.batchSimulation(new ICVC.BatchItem[](0));

        cvc.setImpersonateLock(false);

        address controller = address(new Vault(cvc));
        address collateral = address(new VaultMalicious(cvc));

        vm.prank(alice);
        cvc.enableController(alice, controller);

        vm.prank(alice);
        cvc.enableCollateral(alice, collateral);

        // internal batch in the malicious vault reverts with CVC_ImpersonateReentrancy error,
        // check VaultMalicious implementation
        VaultMalicious(collateral).setExpectedErrorSelector(
            CreditVaultConnector.CVC_ImpersonateReentrancy.selector
        );

        vm.prank(controller);
        vm.expectRevert("callBatch/expected-error");
        cvc.impersonate(
            collateral,
            alice,
            0,
            abi.encodeWithSelector(VaultMalicious.callBatch.selector)
        );
    }

    function test_RevertIfValueExceedsBalance_Batch(
        address alice,
        uint128 seed
    ) external {
        vm.assume(alice != address(0) && alice != address(cvc));
        vm.assume(seed > 0);

        address vault = address(new Vault(cvc));

        ICVC.BatchItem[] memory items = new ICVC.BatchItem[](1);
        items[0].onBehalfOfAccount = alice;
        items[0].targetContract = vault;
        items[0].value = seed;
        items[0].data = abi.encodeWithSelector(
            Vault.requireChecks.selector,
            alice
        );

        // reverts if value exceeds balance
        vm.deal(alice, seed);
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_InvalidValue.selector);
        cvc.batch{value: seed - 1}(items);

        // succeeds if value does not exceed balance
        vm.prank(alice);
        cvc.batch{value: seed}(items);
    }

    function test_BatchRevert_BatchSimulation(address alice) external {
        vm.assume(alice != address(cvc));

        ICVC.BatchItem[] memory items = new ICVC.BatchItem[](1);
        ICVC.BatchItemResult[]
            memory expectedBatchItemsResult = new ICVC.BatchItemResult[](1);
        ICVC.BatchItemResult[]
            memory expectedAccountsStatusResult = new ICVC.BatchItemResult[](1);
        ICVC.BatchItemResult[]
            memory expectedVaultsStatusResult = new ICVC.BatchItemResult[](1);

        address controller = address(new Vault(cvc));

        vm.prank(alice);
        cvc.enableController(alice, controller);

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
        expectedAccountsStatusResult[0].result = abi.encode(
            ICreditVault.checkAccountStatus.selector
        );

        expectedVaultsStatusResult[0].success = true;
        expectedVaultsStatusResult[0].result = abi.encode(
            ICreditVault.checkVaultStatus.selector
        );

        // regular batch doesn't revert
        vm.prank(alice);
        cvc.batch(items);

        {
            vm.prank(alice);
            try cvc.batchRevert(items) {
                assert(false);
            } catch (bytes memory err) {
                assertEq(
                    bytes4(err),
                    CreditVaultConnector.CVC_RevertedBatchResult.selector
                );

                assembly {
                    err := add(err, 4)
                }
                (
                    ICVC.BatchItemResult[] memory batchItemsResult,
                    ICVC.BatchItemResult[] memory accountsStatusResult,
                    ICVC.BatchItemResult[] memory vaultsStatusResult
                ) = abi.decode(
                        err,
                        (
                            ICVC.BatchItemResult[],
                            ICVC.BatchItemResult[],
                            ICVC.BatchItemResult[]
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
                ICVC.BatchItemResult[] memory batchItemsResult,
                ICVC.BatchItemResult[] memory accountsStatusResult,
                ICVC.BatchItemResult[] memory vaultsStatusResult
            ) = cvc.batchSimulation(items);

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
        expectedAccountsStatusResult[0].result = abi.encodeWithSignature(
            "Error(string)",
            "account status violation"
        );

        expectedVaultsStatusResult[0].success = false;
        expectedVaultsStatusResult[0].result = abi.encodeWithSignature(
            "Error(string)",
            "vault status violation"
        );

        // regular batch reverts now
        vm.prank(alice);
        vm.expectRevert(bytes("account status violation"));
        cvc.batch(items);

        {
            vm.prank(alice);
            try cvc.batchRevert(items) {
                assert(false);
            } catch (bytes memory err) {
                assertEq(
                    bytes4(err),
                    CreditVaultConnector.CVC_RevertedBatchResult.selector
                );

                assembly {
                    err := add(err, 4)
                }
                (
                    ICVC.BatchItemResult[] memory batchItemsResult,
                    ICVC.BatchItemResult[] memory accountsStatusResult,
                    ICVC.BatchItemResult[] memory vaultsStatusResult
                ) = abi.decode(
                        err,
                        (
                            ICVC.BatchItemResult[],
                            ICVC.BatchItemResult[],
                            ICVC.BatchItemResult[]
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
                ICVC.BatchItemResult[] memory batchItemsResult,
                ICVC.BatchItemResult[] memory accountsStatusResult,
                ICVC.BatchItemResult[] memory vaultsStatusResult
            ) = cvc.batchSimulation(items);

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
        vm.assume(alice != address(cvc));

        ICVC cvc_noRevert = new CreditVaultConnectorNoRevert();
        vm.prank(alice);
        vm.expectRevert(CreditVaultConnector.CVC_BatchPanic.selector);
        cvc_noRevert.batchSimulation(new ICVC.BatchItem[](0));
    }
}
