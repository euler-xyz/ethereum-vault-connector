# Assertion Invariants

This document describes the invariants being protected by the assertions in this directory.

## Overview

| # | Assertion | Invariant |
|---|-----------|-----------|
| 1 | [VaultSharePriceAssertion](#1-vaultsharepriceassertion) | A vault's share price cannot decrease unless bad debt socialization occurs |
| 2 | [AccountHealthAssertion](#2-accounthealthassertion) | A vault operation cannot make a healthy account unhealthy |
| 3 | [VaultAccountingIntegrityAssertion](#3-vaultaccountingintegrityassertion) | The vault's actual balance must always be at least its cash |
| 4 | [VaultExchangeRateSpikeAssertion](#4-vaultexchangeratespikeassertion) | The exchange rate cannot suddenly change by more than 5% in a single transaction |
| 5 | [VaultAssetTransferAccountingAssertion](#5-vaultassettransferaccountingassertion) | Any asset transferred from a vault must be accompanied by a corresponding Withdraw or Borrow event |

---

## 1. VaultSharePriceAssertion

**Contract File:** [VaultSharePriceAssertion.a.sol](src/VaultSharePriceAssertion.a.sol)

### Invariant: VAULT_SHARE_PRICE_INVARIANT

**Description:** A vault's share price cannot decrease unless bad debt socialization occurs.

**Mathematical Definition:**

```
For any vault V and any transaction T that interacts with V:

Let:
- SP_pre(V) = totalAssets(V) * 1e18 / totalSupply(V) before transaction T
- SP_post(V) = totalAssets(V) * 1e18 / totalSupply(V) after transaction T
- BDS(T,V) = true if bad debt socialization events occurred for vault V in transaction T

Then the following invariant must hold:
SP_post(V) >= SP_pre(V) ∨ BDS(T,V)
```

### What This Protects Against

- **Malicious vault implementations** that steal funds from depositors
- **Protocol bugs** that cause unexpected share price decreases
- **Economic attacks** that drain vault value
- **Implementation errors** in vault logic

### What This Allows

- **Normal vault operations** (deposits, withdrawals, yield generation)
- **Bad debt socialization** (as designed in the Euler protocol)
- **Legitimate share price increases** from yield or other mechanisms

### Edge Cases Handled

- Non-contract addresses (skipped)
- Vaults that don't implement ERC4626 (graceful failure)
- Zero total supply (share price = 0)
- Failed static calls to vault functions

## 2. AccountHealthAssertion

**Contract File:** [AccountHealthAssertion.a.sol](src/AccountHealthAssertion.a.sol)

### Invariant: ACCOUNT_HEALTH_INVARIANT

**Description:** No vault action can make a healthy account unhealthy.

**Mathematical Definition:**

```
For any vault V, any account A, and any transaction T that interacts with V through EVC:

Let:
- (CV_pre(A), LV_pre(A)) = V.accountLiquidity(A, false) before transaction T
  where CV = collateralValue, LV = liabilityValue
- (CV_post(A), LV_post(A)) = V.accountLiquidity(A, false) after transaction T
- isHealthy(A) = CV(A) >= LV(A)

Then the following invariant must hold:
isHealthy_pre(A) → isHealthy_post(A)

In plain English:
"If an account was healthy before a vault operation, it must remain healthy afterwards"

Or equivalently (contrapositive):
"A vault operation cannot make a healthy account unhealthy"
```

### What This Protects Against

- **Unauthorized account liquidation** - Prevents vault operations from making accounts vulnerable to liquidation
- **Collateral manipulation attacks** - Detects operations that improperly reduce account health
- **Protocol bugs** that cause unexpected solvency violations
- **Cross-vault health impacts** - Catches when operations on one vault (e.g., withdrawing collateral) affect account health at controller vaults
- **Economic attacks** that drain account value below safe thresholds

### What This Allows

- **Normal vault operations** that maintain or improve account health
- **Health-neutral operations** like transfers between healthy accounts
- **Legitimate health improvements** from deposits, repayments, etc.

### Health Check Mechanism

For each affected account A, the assertion checks health at TWO locations:

#### Check 1: Direct vault check

- The vault V that was directly called in the transaction

#### Check 2: Controller vault checks

- All controller vaults for account A (via `evc.getControllers(A)`)
- This is critical because operations on collateral vaults affect controller health

#### Why both checks are needed

When a user withdraws collateral from VaultA (collateral vault), the controller VaultB's view of account health changes even though VaultB wasn't directly touched. This is by EVC design: `checkAccountStatus()` receives all enabled collaterals and prices them together. The controller must evaluate the complete picture of account solvency.

**Example:**

```text
Initial state:
- User has 100 tokens in VaultA (collateral)
- User borrowed 80 tokens from VaultB (controller)
- Health at VaultB: collateral (100) >= liability (80) ✅

Operation: Withdraw 30 tokens from VaultA
- VaultB is NOT in the batch operations
- But VaultB's health check will now see: collateral (70) < liability (80) ❌

Assertion: Checks health at BOTH VaultA and VaultB, catches the violation
```

### Edge Cases Handled

- **Non-vault contracts** (no `accountLiquidity()` function) - Skipped gracefully
- **Accounts without a controller** - Cannot query health, skipped
- **Already-unhealthy accounts** (CV < LV before transaction) - Skipped, invariant only prevents healthy→unhealthy transitions
- **Failed `accountLiquidity()` calls** - Graceful skip (vault may not support interface)
- **Multiple accounts in single transaction** - All unique accounts validated
- **Unknown vault function selectors** - Non-monitored functions are ignored
- **Liquidations** - Skipped for now (operate on already-unhealthy accounts)

## 3. VaultAccountingIntegrityAssertion

**Contract File:** [VaultAccountingIntegrityAssertion.a.sol](src/VaultAccountingIntegrityAssertion.a.sol)

### Invariant: VAULT_ACCOUNTING_INTEGRITY_INVARIANT

**Description:** A vault's actual asset balance must always be at least its internal cash accounting.

**Mathematical Definition:**

```
For any vault V and any transaction T that interacts with V:

Let:
- asset = V.asset()
- balance = asset.balanceOf(V) after transaction T
- cash = V.cash() after transaction T

Then the following invariant must hold:
   balance >= cash
```

### What This Protects Against

- **Asset theft** where tokens leave the vault without cash being decremented
- **Accounting bugs** where cash is inflated without corresponding tokens
- **Implementation errors** in withdrawal logic that fail to update cash
- **Unauthorized asset extraction** without proper accounting updates
- **Exploits** that transfer assets out while leaving cash unchanged

### What This Allows

- **Normal deposits** (balance and cash both increase)
- **Normal withdrawals** (balance and cash both decrease, balance remains >= cash)
- **Borrows** (balance and cash both decrease by same amount, balance remains >= cash)
- **Repays** (balance and cash both increase by same amount)
- **Donations to vault** (balance > cash is acceptable - unaccounted assets can be claimed via skim())

### Edge Cases Handled

- **Non-EVault contracts** (no asset() or cash() functions) - Skipped gracefully
- **Failed staticcalls** - Skipped gracefully
- **Balance > cash** - Allowed (unaccounted assets can be skimmed)
- **Multiple operations in batch** - Single check performed after all operations complete
- **Vaults starting in bad state** - Caught immediately by check

### Relationship to VaultAssetTransferAccountingAssertion

These two assertions provide complementary checks: VaultAccountingIntegrityAssertion validates state (balance >= cash) while VaultAssetTransferAccountingAssertion validates events (Transfer events match Withdraw/Borrow events).

## 4. VaultExchangeRateSpikeAssertion

**Contract File:** [VaultExchangeRateSpikeAssertion.a.sol](src/VaultExchangeRateSpikeAssertion.a.sol)

### Invariant: VAULT_EXCHANGE_RATE_SPIKE_INVARIANT

**Description:** A vault's exchange rate (assets per share) cannot increase or decrease by more than a threshold percentage in a single transaction.

**Mathematical Definition:**

```
For any vault V and any transaction T that interacts with V:

Let:
- totalAssets_pre = V.totalAssets() before transaction T
- totalSupply_pre = V.totalSupply() before transaction T
- totalAssets_post = V.totalAssets() after transaction T
- totalSupply_post = V.totalSupply() after transaction T
- exchangeRate_pre = totalAssets_pre * 1e18 / totalSupply_pre
- exchangeRate_post = totalAssets_post * 1e18 / totalSupply_post
- changePct = |exchangeRate_post - exchangeRate_pre| * 100 / exchangeRate_pre

Then the following invariant must hold:
changePct <= THRESHOLD (5%)
```

### What This Protects Against

- **Donation attacks** where attackers manipulate share price
- **Price manipulation** through flash loans
- **Accounting bugs** that cause sudden rate changes
- **Exploits** that drain value from existing depositors

### What This Allows

- **Normal interest accrual** (gradual rate increases)
- **Small rate fluctuations** from deposits/withdrawals
- **Bad debt socialization** (covered by VaultSharePriceAssertion)

### Edge Cases Handled

- **Zero total supply** (new or empty vault) - Skipped
- **First deposit into empty vault** - Skipped
- **Exchange rate changes in both directions** - Both checked against threshold

### Exemptions

- **`skim()` operations** - Exempted (claims unaccounted assets, legitimately changes rate)

## 5. VaultAssetTransferAccountingAssertion

**Contract File:** [VaultAssetTransferAccountingAssertion.a.sol](src/VaultAssetTransferAccountingAssertion.a.sol)

### Invariant: VAULT_ASSET_TRANSFER_ACCOUNTING_INVARIANT

**Description:** Any asset tokens leaving the vault must be accompanied by a corresponding Withdraw or Borrow event with matching amount.

**Mathematical Definition:**

```
For any vault V, any transaction T, and the asset token A = V.asset():

Let:
- transferEvents = all Transfer(address from, address to, uint256 amount) events
                   emitted by A where from == V in transaction T
- withdrawEvents = all Withdraw(address sender, address receiver, address owner,
                                uint256 assets, uint256 shares) events
                   emitted by V in transaction T
- borrowEvents = all Borrow(address account, uint256 assets) events
                 emitted by V in transaction T
- totalTransferred = sum of all amounts in transferEvents
- totalWithdrawn = sum of all assets in withdrawEvents
- totalBorrowed = sum of all assets in borrowEvents
- totalAccounted = totalWithdrawn + totalBorrowed

Then the following invariant must hold:
totalTransferred <= totalAccounted
```

### What This Protects Against

- **Unauthorized asset extraction** without proper event emission
- **Exploits** that bypass normal withdrawal/borrow flows
- **Implementation bugs** where assets are transferred without events
- **Malicious vault code** that silently drains funds
- **Accounting bypasses** that don't update internal state properly

### What This Allows

- **Normal withdrawals** with Withdraw events
- **Normal borrows** with Borrow events
- **Multiple operations** in same transaction (sum of all transfers matched against sum of all events)
- **Flash loans** (assets transferred out and returned in same tx, net should match events)

### Edge Cases Handled

- **Multiple transfers in one transaction** - Sum all transfers and all accounting events
- **Flash loans** - Assets transferred out and back; net effect should still be accounted for by events
- **Transfers to vault (deposits/repays)** - Only check transfers OUT (where `from == vault`)
- **Fee transfers** - Should be accompanied by fee-related events or included in withdrawal amounts
- **Non-EVault contracts** - Skipped gracefully (no Withdraw/Borrow events)
- **Failed event parsing** - Skipped gracefully
- **Zero amount transfers** - Handled correctly in summation

### Relationship to VaultAccountingIntegrityAssertion

These two assertions provide complementary checks: VaultAccountingIntegrityAssertion validates state (balance >= cash) while VaultAssetTransferAccountingAssertion validates events (Transfer events match Withdraw/Borrow events).
