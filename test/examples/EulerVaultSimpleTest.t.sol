// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

import {DSTestPlus} from "solmate/test/utils/DSTestPlus.sol";
import {MockERC20} from "solmate/test/utils/mocks/MockERC20.sol";
import "forge-std/Test.sol";
import "../../src/examples/CreditVaultSimple.sol";
import "../../src/CreditVaultProtocol.sol";

contract CreditVaultSimpleTest is DSTestPlus {
    ICVP cvp;
    MockERC20 underlying;
    CreditVaultSimple vault;

    error NotAuthorized();
    error ControllerDisabled();
    
    function setUp() public {
        cvp = new CreditVaultProtocol();
        underlying = new MockERC20("Mock Token", "TKN", 18);
        vault = new CreditVaultSimple(cvp, underlying, "Mock Token Vault", "vwTKN");
    }

    function invariantMetadata() public {
        assertEq(vault.name(), "Mock Token Vault");
        assertEq(vault.symbol(), "vwTKN");
        assertEq(vault.decimals(), 18);
    }

    function testCVPIntegration(address alice, address bob) public {
        hevm.assume(uint160(alice )| 0xff != uint160(bob )| 0xff);

        // check if possible to enable and disable controller right away
        assertTrue(!cvp.isControllerEnabled(alice, address(vault)));

        hevm.prank(alice);
        cvp.enableController(alice, address(vault));
        assertTrue(cvp.isControllerEnabled(alice, address(vault)));

        // bob should be able to disable controller on behalf of alice 
        // if she doesn't have any outstanting debt
        hevm.prank(bob);
        vault.disableController(alice);
        assertTrue(!cvp.isControllerEnabled(alice, address(vault)));

        // the account status check must return true because alice doesn't have any debt
        (bool isValid,) = vault.checkAccountStatus(alice, new address[](0));
        assertTrue(isValid);

        // check vault status hooks
        hevm.prank(address(cvp));
        vault.checkVaultStatus();
    }
        
    function testDepositDoesntAuthenticateCVP(address alice, address bob) external {
        hevm.assume(uint160(alice )| 0xff != uint160(bob )| 0xff);

        hevm.prank(alice);
        (
            bool success, 
            bytes memory result
        ) = cvp.call(address(vault), alice, abi.encodeWithSelector(0x6e553f65, 10, bob));  // deposit(uint256,address)
    
        assertNotEq(bytes4(result), NotAuthorized.selector);

        hevm.prank(alice);
        (
            success, 
            result
        ) = cvp.call(address(vault), alice, abi.encodeWithSelector(0x2e2d2984, 10, bob, address(0)));  // deposit(uint256,address,address)
    
        assertNotEq(bytes4(result), NotAuthorized.selector);

        hevm.prank(alice);
        (
            success, 
            result
        ) = cvp.call(address(vault), alice, abi.encodeWithSelector(0x2e2d2984, 10, address(0), bob));  // deposit(uint256,address,address)
    
        assertNotEq(bytes4(result), NotAuthorized.selector);
    }

    function testMintDoesntAuthenticateCVP(address alice, address bob) external {
        hevm.assume(uint160(alice )| 0xff != uint160(bob )| 0xff);

        hevm.prank(alice);
        (
            bool success, 
            bytes memory result
        ) = cvp.call(address(vault), alice, abi.encodeWithSelector(0x94bf804d, 10, bob));  // mint(uint256,address)
    
        assertNotEq(bytes4(result), NotAuthorized.selector);

        hevm.prank(alice);
        (
            success, 
            result
        ) = cvp.call(address(vault), alice, abi.encodeWithSelector(0xda39b3e7, 10, bob, address(0)));  // mint(uint256,address,address)
    
        assertNotEq(bytes4(result), NotAuthorized.selector);

        hevm.prank(alice);
        (
            success, 
            result
        ) = cvp.call(address(vault), alice, abi.encodeWithSelector(0xda39b3e7, 10, address(0), bob));  // mint(uint256,address,address)
    
        assertNotEq(bytes4(result), NotAuthorized.selector);
    }

    function testTransferAuthenticatesCVP(address alice) external {
        hevm.assume(uint160(alice )| 0xff != uint160(address(cvp) )| 0xff);

        hevm.prank(alice);
        (
            bool success, 
            bytes memory result
        ) = cvp.call(address(vault), alice, abi.encodeWithSelector(vault.transfer.selector, address(0), 10));
    
        assertFalse(success);
        assertEq(bytes4(result), NotAuthorized.selector);
    }

    function testTransferFromAuthenticatesCVP(address alice, address bob) external {
        hevm.assume(uint160(alice )| 0xff != uint160(bob )| 0xff);

        hevm.prank(alice);
        (
            bool success, 
            bytes memory result
        ) = cvp.call(address(vault), alice, abi.encodeWithSelector(vault.transferFrom.selector, bob, address(0), 10));
    
        assertFalse(success);
        assertEq(bytes4(result), NotAuthorized.selector);
    }

    function testWithdrawAuthenticatesCVP(address alice, address bob) external {
        hevm.assume(uint160(alice )| 0xff != uint160(bob )| 0xff);

        hevm.prank(alice);
        (
            bool success, 
            bytes memory result
        ) = cvp.call(address(vault), alice, abi.encodeWithSelector(vault.withdraw.selector, 10, address(0), bob));
    
        assertFalse(success);
        assertEq(bytes4(result), NotAuthorized.selector);
    }

    function testRedeemAuthenticatesCVP(address alice, address bob) external {
        hevm.assume(uint160(alice )| 0xff != uint160(bob )| 0xff);

        hevm.prank(alice);
        (
            bool success, 
            bytes memory result
        ) = cvp.call(address(vault), alice, abi.encodeWithSelector(vault.redeem.selector, 10, address(0), bob));
    
        assertFalse(success);
        assertEq(bytes4(result), NotAuthorized.selector);
    }

    function testWithdrawToReservesAuthenticatesCVP(address alice, address bob) external {
        hevm.assume(uint160(alice )| 0xff != uint160(bob )| 0xff);

        hevm.prank(alice);
        (
            bool success, 
            bytes memory result
        ) = cvp.call(address(vault), alice, abi.encodeWithSelector(vault.withdrawToReserves.selector, 10, bob));
    
        assertFalse(success);
        assertEq(bytes4(result), NotAuthorized.selector);
    }

    function testRedeemToReservesAuthenticatesCVP(address alice, address bob) external {
        hevm.assume(uint160(alice )| 0xff != uint160(bob )| 0xff);

        hevm.prank(alice);
        (
            bool success, 
            bytes memory result
        ) = cvp.call(address(vault), alice, abi.encodeWithSelector(vault.redeemToReserves.selector, 10, bob));
    
        assertFalse(success);
        assertEq(bytes4(result), NotAuthorized.selector);
    }

    function testWithdrawReservesAuthenticatesCVP(address alice) external {
        hevm.prank(alice);
        (
            bool success, 
            bytes memory result
        ) = cvp.call(address(vault), alice, abi.encodeWithSelector(vault.withdrawReserves.selector, 10, address(0)));
    
        assertFalse(success);
        assertEq(bytes4(result), NotAuthorized.selector);
    }

    function testRedeemReservesAuthenticatesCVP(address alice) external {
        hevm.prank(alice);
        (
            bool success, 
            bytes memory result
        ) = cvp.call(address(vault), alice, abi.encodeWithSelector(vault.redeemReserves.selector, 10, address(0)));
    
        assertFalse(success);
        assertEq(bytes4(result), NotAuthorized.selector);
    }

    function testMetadata(address cvpAddr, string calldata name, string calldata symbol) public {
        CreditVaultSimple vlt = new CreditVaultSimple(ICVP(cvpAddr), underlying, name, symbol);
        assertEq(address(vlt.cvp()), cvpAddr);
        assertEq(vlt.name(), name);
        assertEq(vlt.symbol(), symbol);
        assertEq(address(vlt.asset()), address(underlying));
    }

    function testSingleDepositWithdraw(uint128 amount, uint seed) public {
        if (amount == 0) amount = 1;

        uint256 aliceUnderlyingAmount = amount;

        address alice = address(0xABCD);

        underlying.mint(alice, aliceUnderlyingAmount);

        hevm.prank(alice);
        underlying.approve(address(vault), aliceUnderlyingAmount);
        assertEq(underlying.allowance(alice, address(vault)), aliceUnderlyingAmount);

        uint256 alicePreDepositBal = underlying.balanceOf(alice);

        hevm.prank(alice);
        uint256 aliceShareAmount;
        if (seed % 3 == 0) {
            aliceShareAmount = vault.deposit(aliceUnderlyingAmount, alice);
        } else if (seed % 2 == 0) { 
            aliceShareAmount = vault.deposit(aliceUnderlyingAmount, alice, alice);
        } else {
            (bool success, bytes memory result) = cvp.call(
                address(vault),
                alice,
                abi.encodeWithSelector(
                    0x2e2d2984, //"function deposit(uint256,address,address) public returns (uint256)",
                    aliceUnderlyingAmount,
                    alice,
                    alice
                )
            );
            assert(success);
            aliceShareAmount = abi.decode(result, (uint256));
        }

        // Expect exchange rate to be 1:1 on initial deposit.
        assertEq(aliceUnderlyingAmount, aliceShareAmount);
        assertEq(vault.previewWithdraw(aliceShareAmount), aliceUnderlyingAmount);
        assertEq(vault.previewDeposit(aliceUnderlyingAmount), aliceShareAmount);
        assertEq(vault.totalSupply(), aliceShareAmount);
        assertEq(vault.totalAssets(), aliceUnderlyingAmount);
        assertEq(vault.balanceOf(alice), aliceShareAmount);
        assertEq(vault.convertToAssets(vault.balanceOf(alice)), aliceUnderlyingAmount);
        assertEq(underlying.balanceOf(alice), alicePreDepositBal - aliceUnderlyingAmount);

        hevm.prank(alice);
        if (seed % 2 == 0) {
            vault.withdraw(aliceUnderlyingAmount, alice, alice);
        } else {
            (bool success,) = cvp.call(
                address(vault),
                alice,
                abi.encodeWithSelector(
                    vault.withdraw.selector,
                    aliceUnderlyingAmount,
                    alice,
                    alice
                )
            );
            assert(success);
        }

        assertEq(vault.totalAssets(), 0);
        assertEq(vault.balanceOf(alice), 0);
        assertEq(vault.convertToAssets(vault.balanceOf(alice)), 0);
        assertEq(underlying.balanceOf(alice), alicePreDepositBal);
    }

    function testSingleMintRedeem(uint128 amount, uint seed) public {
        if (amount == 0) amount = 1;

        uint256 aliceShareAmount = amount;

        address alice = address(0xABCD);

        underlying.mint(alice, aliceShareAmount);

        hevm.prank(alice);
        underlying.approve(address(vault), aliceShareAmount);
        assertEq(underlying.allowance(alice, address(vault)), aliceShareAmount);

        uint256 alicePreDepositBal = underlying.balanceOf(alice);

        hevm.prank(alice);
        uint256 aliceUnderlyingAmount;
        if (seed % 3 == 0) {
            aliceUnderlyingAmount = vault.mint(aliceShareAmount, alice);
        } else if (seed % 2 == 0) { 
            aliceUnderlyingAmount = vault.mint(aliceShareAmount, alice, alice);
        } else {
            (bool success, bytes memory result) = cvp.call(
                address(vault),
                alice,
                abi.encodeWithSelector(
                    0xda39b3e7, //"function mint(uint256,address,address) public returns (uint256)",
                    aliceShareAmount,
                    alice,
                    alice
                )
            );
            assert(success);
            aliceUnderlyingAmount = abi.decode(result, (uint256));
        }

        // Expect exchange rate to be 1:1 on initial mint.
        assertEq(aliceShareAmount, aliceUnderlyingAmount);
        assertEq(vault.previewWithdraw(aliceShareAmount), aliceUnderlyingAmount);
        assertEq(vault.previewDeposit(aliceUnderlyingAmount), aliceShareAmount);
        assertEq(vault.totalSupply(), aliceShareAmount);
        assertEq(vault.totalAssets(), aliceUnderlyingAmount);
        assertEq(vault.balanceOf(alice), aliceUnderlyingAmount);
        assertEq(vault.convertToAssets(vault.balanceOf(alice)), aliceUnderlyingAmount);
        assertEq(underlying.balanceOf(alice), alicePreDepositBal - aliceUnderlyingAmount);

        hevm.prank(alice);
        if (seed % 2 == 0) {
            vault.redeem(aliceShareAmount, alice, alice);
        } else {
            (bool success,) = cvp.call(
                address(vault),
                alice,
                abi.encodeWithSelector(
                    vault.redeem.selector,
                    aliceShareAmount,
                    alice,
                    alice
                )
            );
            assert(success);
        }

        assertEq(vault.totalAssets(), 0);
        assertEq(vault.balanceOf(alice), 0);
        assertEq(vault.convertToAssets(vault.balanceOf(alice)), 0);
        assertEq(underlying.balanceOf(alice), alicePreDepositBal);
    }

    function testMultipleMintDepositRedeemWithdraw(uint seed) public {
        // Scenario:
        // A = Alice, B = Bob
        //  ________________________________________________________
        // | Vault shares | A share | A assets | B share | B assets |
        // |========================================================|
        // | 1. Alice mints 2000 shares (costs 2000 tokens)         |
        // |--------------|---------|----------|---------|----------|
        // |         2000 |    2000 |     2000 |       0 |        0 |
        // |--------------|---------|----------|---------|----------|
        // | 2. Bob deposits 4000 tokens (mints 4000 shares)        |
        // |--------------|---------|----------|---------|----------|
        // |         6000 |    2000 |     2000 |    4000 |     4000 |
        // |--------------|---------|----------|---------|----------|
        // | 3. Vault mutates by +3000 tokens...                    |
        // |    (simulated yield returned from strategy)...         |
        // |--------------|---------|----------|---------|----------|
        // |         6000 |    2000 |     3000 |    4000 |     6000 |
        // |--------------|---------|----------|---------|----------|
        // | 4. Alice deposits 2000 tokens (mints 1333 shares)      |
        // |--------------|---------|----------|---------|----------|
        // |         7333 |    3333 |     4999 |    4000 |     6000 |
        // |--------------|---------|----------|---------|----------|
        // | 5. Bob mints 2000 shares (costs 3001 assets)           |
        // |    NOTE: Bob's assets spent got rounded up             |
        // |    NOTE: Alice's vault assets got rounded up           |
        // |--------------|---------|----------|---------|----------|
        // |         9333 |    3333 |     5000 |    6000 |     9000 |
        // |--------------|---------|----------|---------|----------|
        // | 6. Vault mutates by +3000 tokens...                    |
        // |    (simulated yield returned from strategy)            |
        // |    NOTE: Vault holds 17001 tokens, but sum of          |
        // |          assetsOf() is 17000.                          |
        // |--------------|---------|----------|---------|----------|
        // |         9333 |    3333 |     6071 |    6000 |    10929 |
        // |--------------|---------|----------|---------|----------|
        // | 7. Alice redeem 1333 shares (2428 assets)              |
        // |--------------|---------|----------|---------|----------|
        // |         8000 |    2000 |     3643 |    6000 |    10929 |
        // |--------------|---------|----------|---------|----------|
        // | 8. Bob withdraws 2928 assets (1608 shares)             |
        // |--------------|---------|----------|---------|----------|
        // |         6392 |    2000 |     3643 |    4392 |     8000 |
        // |--------------|---------|----------|---------|----------|
        // | 9. Alice withdraws 3643 assets (2000 shares)           |
        // |    NOTE: Bob's assets have been rounded back up        |
        // |--------------|---------|----------|---------|----------|
        // |         4392 |       0 |        0 |    4392 |     8001 |
        // |--------------|---------|----------|---------|----------|
        // | 10. Bob redeem 4392 shares (8001 tokens)               |
        // |--------------|---------|----------|---------|----------|
        // |            0 |       0 |        0 |       0 |        0 |
        // |______________|_________|__________|_________|__________|

        address alice = address(0xABCD);
        address bob = address(0xDCBA);

        uint256 mutationUnderlyingAmount = 3000;

        underlying.mint(alice, 4000);

        hevm.prank(alice);
        underlying.approve(address(vault), 4000);

        assertEq(underlying.allowance(alice, address(vault)), 4000);

        underlying.mint(bob, 7001);

        hevm.prank(bob);
        underlying.approve(address(vault), 7001);

        assertEq(underlying.allowance(bob, address(vault)), 7001);

        // 1. Alice mints 2000 shares (costs 2000 tokens)
        hevm.prank(alice);
        uint256 aliceUnderlyingAmount;
        if (seed % 3 == 0) {
            aliceUnderlyingAmount = vault.mint(2000, alice);
        } else if (seed % 2 == 0) { 
            aliceUnderlyingAmount = vault.mint(2000, alice, alice);
        } else {
            (bool success, bytes memory result) = cvp.call(
                address(vault),
                alice,
                abi.encodeWithSelector(
                    0xda39b3e7, //"function mint(uint256,address,address) public returns (uint256)",
                    2000,
                    alice,
                    alice
                )
            );
            assert(success);
            aliceUnderlyingAmount = abi.decode(result, (uint256));
        }

        uint256 aliceShareAmount = vault.previewDeposit(aliceUnderlyingAmount);

        // Expect to have received the requested mint amount.
        assertEq(aliceShareAmount, 2000);
        assertEq(vault.balanceOf(alice), aliceShareAmount);
        assertEq(vault.convertToAssets(vault.balanceOf(alice)), aliceUnderlyingAmount);
        assertEq(vault.convertToShares(aliceUnderlyingAmount), vault.balanceOf(alice));

        // Expect a 1:1 ratio before mutation.
        assertEq(aliceUnderlyingAmount, 2000);

        // Sanity check.
        assertEq(vault.totalSupply(), aliceShareAmount);
        assertEq(vault.totalAssets(), aliceUnderlyingAmount);

        // 2. Bob deposits 4000 tokens (mints 4000 shares)
        hevm.prank(bob);
        uint256 bobShareAmount;
        if (seed % 3 == 0) {
            bobShareAmount = vault.deposit(4000, bob);
        } else if (seed % 2 == 0) { 
            bobShareAmount = vault.deposit(4000, bob, bob);
        } else {
            (bool success, bytes memory result) = cvp.call(
                address(vault),
                bob,
                abi.encodeWithSelector(
                    0x2e2d2984, //"function deposit(uint256,address,address) public returns (uint256)",
                    4000,
                    bob,
                    bob
                )
            );
            assert(success);
            bobShareAmount = abi.decode(result, (uint256));
        }

        uint256 bobUnderlyingAmount = vault.previewWithdraw(bobShareAmount);

        // Expect to have received the requested underlying amount.
        assertEq(bobUnderlyingAmount, 4000);
        assertEq(vault.balanceOf(bob), bobShareAmount);
        assertEq(vault.convertToAssets(vault.balanceOf(bob)), bobUnderlyingAmount);
        assertEq(vault.convertToShares(bobUnderlyingAmount), vault.balanceOf(bob));

        // Expect a 1:1 ratio before mutation.
        assertEq(bobShareAmount, bobUnderlyingAmount);

        // Sanity check.
        {
            uint256 preMutationShareBal = aliceShareAmount + bobShareAmount;
            uint256 preMutationBal = aliceUnderlyingAmount + bobUnderlyingAmount;
            assertEq(vault.totalSupply(), preMutationShareBal);
            assertEq(vault.totalAssets(), preMutationBal);
            assertEq(vault.totalSupply(), 6000);
            assertEq(vault.totalAssets(), 6000);

            // 3. Vault mutates by +3000 tokens...                    |
            //    (simulated yield returned from strategy)...
            // The Vault now contains more tokens than deposited which causes the exchange rate to change.
            // Alice share is 33.33% of the Vault, Bob 66.66% of the Vault.
            // Alice's share count stays the same but the underlying amount changes from 2000 to 3000.
            // Bob's share count stays the same but the underlying amount changes from 4000 to 6000.
            underlying.mint(address(vault), mutationUnderlyingAmount);
            assertEq(vault.totalSupply(), preMutationShareBal);
            assertEq(vault.totalAssets(), preMutationBal + mutationUnderlyingAmount);
            assertEq(vault.balanceOf(alice), aliceShareAmount);
            assertEq(
                vault.convertToAssets(vault.balanceOf(alice)),
                aliceUnderlyingAmount + (mutationUnderlyingAmount / 3) * 1
            );
            assertEq(vault.balanceOf(bob), bobShareAmount);
            assertEq(vault.convertToAssets(vault.balanceOf(bob)), bobUnderlyingAmount + (mutationUnderlyingAmount / 3) * 2);
        }

        // 4. Alice deposits 2000 tokens (mints 1333 shares)
        hevm.prank(alice);
        if (seed % 3 == 0) {
            vault.deposit(2000, alice);
        } else if (seed % 2 == 0) { 
            vault.deposit(2000, alice, alice);
        } else {
            (bool success,) = cvp.call(
                address(vault),
                alice,
                abi.encodeWithSelector(
                    0x2e2d2984, //"function deposit(uint256,address,address) public returns (uint256)",
                    2000,
                    alice,
                    alice
                )
            );
            assert(success);
        }

        assertEq(vault.totalSupply(), 7333);
        assertEq(vault.balanceOf(alice), 3333);
        assertEq(vault.convertToAssets(vault.balanceOf(alice)), 4999);
        assertEq(vault.balanceOf(bob), 4000);
        assertEq(vault.convertToAssets(vault.balanceOf(bob)), 6000);

        // 5. Bob mints 2000 shares (costs 3001 assets)
        // NOTE: Bob's assets spent got rounded up
        // NOTE: Alices's vault assets got rounded up
        hevm.prank(bob);
        if (seed % 3 == 0) {
            vault.mint(2000, bob);
        } else if (seed % 2 == 0) { 
            vault.mint(2000, bob, bob);
        } else {
            (bool success,) = cvp.call(
                address(vault),
                bob,
                abi.encodeWithSelector(
                    0xda39b3e7, //"function mint(uint256,address,address) public returns (uint256)",
                    2000,
                    bob,
                    bob
                )
            );
            assert(success);
        }

        assertEq(vault.totalSupply(), 9333);
        assertEq(vault.balanceOf(alice), 3333);
        assertEq(vault.convertToAssets(vault.balanceOf(alice)), 5000);
        assertEq(vault.balanceOf(bob), 6000);
        assertEq(vault.convertToAssets(vault.balanceOf(bob)), 9000);

        // Sanity checks:
        // Alice and bob should have spent all their tokens now
        assertEq(underlying.balanceOf(alice), 0);
        assertEq(underlying.balanceOf(bob), 0);
        // Assets in vault: 4k (alice) + 7k (bob) + 3k (yield) + 1 (round up)
        assertEq(vault.totalAssets(), 14001);

        // 6. Vault mutates by +3000 tokens
        // NOTE: Vault holds 17001 tokens, but sum of assetsOf() is 17000.
        underlying.mint(address(vault), mutationUnderlyingAmount);
        assertEq(vault.totalAssets(), 17001);
        assertEq(vault.convertToAssets(vault.balanceOf(alice)), 6071);
        assertEq(vault.convertToAssets(vault.balanceOf(bob)), 10929);

        // 7. Alice redeem 1333 shares (2428 assets)
        hevm.prank(alice);
        if (seed % 2 == 0) {
            vault.redeem(1333, alice, alice);
        } else {
            (bool success,) = cvp.call(
                address(vault),
                alice,
                abi.encodeWithSelector(
                    vault.redeem.selector,
                    1333,
                    alice,
                    alice
                )
            );
            assert(success);
        }

        assertEq(underlying.balanceOf(alice), 2428);
        assertEq(vault.totalSupply(), 8000);
        assertEq(vault.totalAssets(), 14573);
        assertEq(vault.balanceOf(alice), 2000);
        assertEq(vault.convertToAssets(vault.balanceOf(alice)), 3643);
        assertEq(vault.balanceOf(bob), 6000);
        assertEq(vault.convertToAssets(vault.balanceOf(bob)), 10929);

        // 8. Bob withdraws 2929 assets (1608 shares)
        hevm.prank(bob);
        if (seed % 2 == 0) {
            vault.withdraw(2929, bob, bob);
        } else {
            (bool success,) = cvp.call(
                address(vault),
                bob,
                abi.encodeWithSelector(
                    vault.withdraw.selector,
                    2929,
                    bob,
                    bob
                )
            );
            assert(success);
        }

        assertEq(underlying.balanceOf(bob), 2929);
        assertEq(vault.totalSupply(), 6392);
        assertEq(vault.totalAssets(), 11644);
        assertEq(vault.balanceOf(alice), 2000);
        assertEq(vault.convertToAssets(vault.balanceOf(alice)), 3643);
        assertEq(vault.balanceOf(bob), 4392);
        assertEq(vault.convertToAssets(vault.balanceOf(bob)), 8000);

        // 9. Alice withdraws 3643 assets (2000 shares)
        // NOTE: Bob's assets have been rounded back up
        hevm.prank(alice);
        if (seed % 2 == 0) {
            vault.withdraw(3643, alice, alice);
        } else {
            (bool success,) = cvp.call(
                address(vault),
                alice,
                abi.encodeWithSelector(
                    vault.withdraw.selector,
                    3643,
                    alice,
                    alice
                )
            );
            assert(success);
        }

        assertEq(underlying.balanceOf(alice), 6071);
        assertEq(vault.totalSupply(), 4392);
        assertEq(vault.totalAssets(), 8001);
        assertEq(vault.balanceOf(alice), 0);
        assertEq(vault.convertToAssets(vault.balanceOf(alice)), 0);
        assertEq(vault.balanceOf(bob), 4392);
        assertEq(vault.convertToAssets(vault.balanceOf(bob)), 8001);

        // 10. Bob redeem 4392 shares (8001 tokens)
        hevm.prank(bob);
        if (seed % 2 == 0) {
            vault.redeem(4392, bob, bob);
        } else {
            (bool success,) = cvp.call(
                address(vault),
                bob,
                abi.encodeWithSelector(
                    vault.redeem.selector,
                    4392,
                    bob,
                    bob
                )
            );
            assert(success);
        }

        assertEq(underlying.balanceOf(bob), 10930);
        assertEq(vault.totalSupply(), 0);
        assertEq(vault.totalAssets(), 0);
        assertEq(vault.balanceOf(alice), 0);
        assertEq(vault.convertToAssets(vault.balanceOf(alice)), 0);
        assertEq(vault.balanceOf(bob), 0);
        assertEq(vault.convertToAssets(vault.balanceOf(bob)), 0);

        // Sanity check
        assertEq(underlying.balanceOf(address(vault)), 0);
    }

    function testFailDepositWithNotEnoughApproval() public {
        underlying.mint(address(this), 0.5e18);
        underlying.approve(address(vault), 0.5e18);
        assertEq(underlying.allowance(address(this), address(vault)), 0.5e18);

        vault.deposit(1e18, address(this));
    }

    function testFailWithdrawWithNotEnoughUnderlyingAmount() public {
        underlying.mint(address(this), 0.5e18);
        underlying.approve(address(vault), 0.5e18);

        vault.deposit(0.5e18, address(this));

        vault.withdraw(1e18, address(this), address(this));
    }

    function testFailRedeemWithNotEnoughShareAmount() public {
        underlying.mint(address(this), 0.5e18);
        underlying.approve(address(vault), 0.5e18);

        vault.deposit(0.5e18, address(this));

        vault.redeem(1e18, address(this), address(this));
    }

    function testFailWithdrawWithNoUnderlyingAmount() public {
        vault.withdraw(1e18, address(this), address(this));
    }

    function testFailRedeemWithNoShareAmount() public {
        vault.redeem(1e18, address(this), address(this));
    }

    function testFailDepositWithNoApproval() public {
        vault.deposit(1e18, address(this));
    }

    function testFailMintWithNoApproval() public {
        vault.mint(1e18, address(this));
    }

    function testFailDepositZero() public {
        vault.deposit(0, address(this));
    }

    function testFailMintZero() public {
        vault.mint(0, address(this));
    }

    function testFailRedeemZero() public {
        vault.redeem(0, address(this), address(this));
    }

    function testFailWithdrawZero() public {
        vault.withdraw(0, address(this), address(this));
    }

    function testVaultInteractionsForSomeoneElse() public {
        // init 2 users with a 1e18 balance
        address alice = address(0xABCD);
        address bob = address(0xDCBA);
        underlying.mint(alice, 1e18);
        underlying.mint(bob, 1e18);

        hevm.prank(alice);
        underlying.approve(address(vault), 1e18);

        hevm.prank(bob);
        underlying.approve(address(vault), 1e18);

        // alice deposits 1e18 for bob
        hevm.prank(alice);
        vault.deposit(1e18, bob);

        assertEq(vault.balanceOf(alice), 0);
        assertEq(vault.balanceOf(bob), 1e18);
        assertEq(underlying.balanceOf(alice), 0);

        // bob mint 1e18 for alice
        hevm.prank(bob);
        vault.mint(1e18, alice);
        assertEq(vault.balanceOf(alice), 1e18);
        assertEq(vault.balanceOf(bob), 1e18);
        assertEq(underlying.balanceOf(bob), 0);

        // alice redeem 1e18 for bob
        hevm.prank(alice);
        vault.redeem(1e18, bob, alice);

        assertEq(vault.balanceOf(alice), 0);
        assertEq(vault.balanceOf(bob), 1e18);
        assertEq(underlying.balanceOf(bob), 1e18);

        // bob withdraw 1e18 for alice
        hevm.prank(bob);
        vault.withdraw(1e18, alice, bob);

        assertEq(vault.balanceOf(alice), 0);
        assertEq(vault.balanceOf(bob), 0);
        assertEq(underlying.balanceOf(alice), 1e18);
    }
}
