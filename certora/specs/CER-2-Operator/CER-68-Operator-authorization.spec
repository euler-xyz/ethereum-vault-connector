import "../utils/IsMustRevertFunction.spec";

methods {
    function getOwnerOf(bytes19) external returns (address) envfree;
    function getOperator(bytes19, address) external returns (uint256) envfree;
    function getAddressPrefix(address) external returns (bytes19) envfree;
    function haveCommonOwner(address account, address otherAccount) external returns (bool) envfree;
}

// if msg.sender is the currentContract, it means we are within permit() and
// we need to use executionContext.getOnBehalfOfAccount() instead.
function actualCaller(env e) returns address {
    if(e.msg.sender == currentContract) {
        return getExecutionContextOnBehalfOfAccount(e);
    } else {
        return e.msg.sender;
    }
}

/**
 * Check that `setOperator(addressPrefix, ...)` can only be called if msg.sender
 * is the owner of the address prefix. Technically, we check that
 * - msg.sender is from the prefix itself and thus a plausible owner
 * - msg.sender is stored as the owner after the function call
 * - the owner before the call was either 0 (not set) or msg.sender already
 * - the bitset is set as it should be.
 */
rule onlyOwnerCanCallSetOperator() {
    env e;

    bytes19 addressPrefix;
    address operator;
    uint256 operatorBitField;

    address ownerBefore = getOwnerOf(addressPrefix);

    address caller = actualCaller(e);

    // call the setOperator() method.
    setOperator(e, addressPrefix, operator, operatorBitField);

    // sender is from the prefix itself and thus plausible to be the owner
    assert(getAddressPrefix(caller) == addressPrefix);
    // the owner before the call was either not set or actualCaller already
    assert(ownerBefore == 0 || ownerBefore == caller);
    // sender is stored as the owner of the address prefix
    assert(caller == getOwnerOf(addressPrefix));
    // make sure the right bitfield was set
    assert(getOperator(addressPrefix, operator) == operatorBitField);
}


// a copy of the internal ownerLookup
ghost mapping(bytes19 => address) ownerLookupGhost {
    init_state axiom forall bytes19 prefix. ownerLookupGhost[prefix] == 0;
}
// makes sure the ownerLookupGhost is updated properly
hook Sstore EthereumVaultConnectorHarness.ownerLookup[KEY bytes19 prefix] address value STORAGE {
    ownerLookupGhost[prefix] = value;
}
// makes sure that reads from ownerLookup after havocs are correct
hook Sload address value EthereumVaultConnectorHarness.ownerLookup[KEY bytes19 prefix] STORAGE {
    require(ownerLookupGhost[prefix] == value);
}

// check that an owner of a prefix is always from that prefix
invariant OwnerIsFromPrefix(bytes19 prefix)
    getOwnerOf(prefix) == 0 || getAddressPrefix(getOwnerOf(prefix)) == prefix
    filtered { 
        f -> !isMustRevertFunction(f) &&
        // We can't handle these functions since they have `CALL`s in them
        f.selector != sig:batch(IEVC.BatchItem[] calldata).selector
        && 
        f.selector != sig:call(address, address, uint256, bytes calldata).selector
    }

/**
  * Checks a liveness property that the owner of an account
  * can succesfully set an operator (under a few assumptions
  * that are spelled out with the "require" statements).
 */
rule theOwnerCanCallSetOperator() {
    env e;

    bytes19 addressPrefix;
    address operator;
    uint256 operatorBitField;

    address owner = getOwnerOf(addressPrefix);
    requireInvariant OwnerIsFromPrefix(addressPrefix);

    // the actual caller (either msg.sender or the onBehalfOfAccount)
    address caller = actualCaller(e);

    // This is a permit self-call:
    if (e.msg.sender == currentContract) {
        // we are within permit() and should use getOnBehalfOfAccount() instead
        caller = getExecutionContextOnBehalfOfAccount(e);
        // the owner is already set, not zero and not EVC
        require(owner == caller && owner != 0 && owner != currentContract);
        // the owner has the proper prefix
        require(getAddressPrefix(owner) == addressPrefix);
    // This is the normal case where the caller is msg.sender:
    } else {
        // just a regular call from msg.sender
        // msg.sender is from the proper prefix
        require(getAddressPrefix(e.msg.sender) == addressPrefix);
        // the owner is not set yet (zero) or identical to msg.sender
        require(owner == 0 || owner == e.msg.sender);
    }

    // The function will revert if any of these assumptions do not hold:
    require(e.msg.value < nativeBalances[e.msg.sender]);
    require operator != 0;
    require !(operator == currentContract);
    require !(haveCommonOwner(caller, operator));

    // the operator can not be from the prefix either
    require(getAddressPrefix(operator) != getAddressPrefix(caller));

    // the current bitfield must be different from what we try to set
    require(getOperator(addressPrefix, operator) != operatorBitField);

    // call the setOperator() method.
    setOperator@withrevert(e, addressPrefix, operator, operatorBitField);
    // check that it does not revert under these assumptions
    assert(!lastReverted);
}

// Only the owner or operator of an account can set the operator of that account
rule onlyOwnerOrOperatorCanCallSetAccountOperator() {
    env e;
    address account;
    address operator;

    address caller = actualCaller(e);

    // call the setAccountOperator method.
    setAccountOperator(e, account, operator, true);

    address owner = haveCommonOwner(account, caller) ? caller : getAccountOwner(e, account);

    // Since setAccountOperator did not revert, the actualCaller
    // must either be the owner or operator
    assert(caller == owner || caller == operator);

}

// A liveness property: an owner or operator of an account
// can successfully call setAccountOperator without it reverting
// (under a few other assumptions which are spelled out with requires)
rule ownerOrOperatorSetAccountOperatorLiveness() {
    env e;
    address account;
    address operator;

    address caller = actualCaller(e);

    address owner = haveCommonOwner(account, caller) ? caller : getAccountOwner(e, account);

    // Assuming the caller is either the owner or operator of the account...
    require caller == owner || caller == operator;

    // And some other assumptions that if violated,
    // will cause the code to revert:
    require(e.msg.value < nativeBalances[e.msg.sender]);
    require operator != 0;
    require !(operator == currentContract);
    require !(haveCommonOwner(caller, operator));

    uint256 bitMask = 1 << require_uint256(require_uint160(owner) ^ require_uint160(account));
    uint256 oldOperatorBitField = getOperatorFromAddress(e, account, operator);
    uint256 newOperatorBitField = oldOperatorBitField | bitMask;
    require newOperatorBitField != oldOperatorBitField;

    //  Call setOperator
    setAccountOperator@withrevert(e, account, operator, true);
    // Check that it does not revert under these conditions
    assert !lastReverted;
}