methods {
    function getOwnerOf(uint152) external returns (address) envfree;
    function getOperator(uint152, address) external returns (uint256) envfree;
    function getAddressPrefix(address) external returns (uint152) envfree;
    function haveCommonOwner(address account, address otherAccount) external returns (bool) envfree;
}

/**
 * EVC Spec #2
 *
 * Check that `setOperator(addressPrefix, ...)` can only be called if msg.sender
 * is the owner of the address prefix. Technically, we check that
 * - msg.sender is from the prefix itself and thus a plausible owner
 * - msg.sender is stored as the owner after the function call
 * - the owner before the call was either 0 (not set) or msg.sender already
 * - the bitset is set as it should be.
 */
rule onlyOwnerCanCallSetOperator() {
    env e;

    uint152 addressPrefix;
    address operator;
    uint256 operatorBitField;

    address ownerBefore = getOwnerOf(addressPrefix);

    // if msg.sender is the currentContract, it means we are within permit() and
    // we need to use executionContext.getOnBehalfOfAccount() instead.
    address actualCaller = e.msg.sender;
    if (e.msg.sender == currentContract) {
        actualCaller = getExecutionContextOnBehalfOfAccount(e);
    }

    // call the setOperator() method.
    setOperator(e, addressPrefix, operator, operatorBitField);

    // sender is from the prefix itself and thus plausible to be the owner
    assert(getAddressPrefix(actualCaller) == addressPrefix);
    // the owner before the call was either not set or actualCaller already
    assert(ownerBefore == 0 || ownerBefore == actualCaller);
    // sender is stored as the owner of the address prefix
    assert(actualCaller == getOwnerOf(addressPrefix));
    // make sure the right bitfield was set
    assert(getOperator(addressPrefix, operator) == operatorBitField);
}

// a copy of the internal ownerLookup
ghost mapping(uint152 => address) ownerLookupGhost {
    init_state axiom forall uint152 prefix. ownerLookupGhost[prefix] == 0;
}
// makes sure the ownerLookupGhost is updated properly
hook Sstore EthereumVaultConnectorHarness.ownerLookup[KEY uint152 prefix] address value STORAGE {
    ownerLookupGhost[prefix] = value;
}
// makes sure that reads from ownerLookup after havocs are correct
hook Sload address value EthereumVaultConnectorHarness.ownerLookup[KEY uint152 prefix] STORAGE {
    require(ownerLookupGhost[prefix] == value);
}

// check that an owner of a prefix is always from that prefix
invariant OwnerIsFromPrefix(uint152 prefix)
    getOwnerOf(prefix) == 0 || getAddressPrefix(getOwnerOf(prefix)) == prefix;

/**
 * Checks the inverse of the above rule: if an attacker tries to call
 * `setOperator()`, the call reverts. We consider the caller an attacker if
 * either if the prefix has no owner yet, but the caller is not from this prefix
 * or if the prefix has an owner that is not the caller.
 */
rule theOwnerCanCallSetOperator() {
    env e;

    // this in an interesting way to revert... *shrug*
    require(e.msg.value < nativeBalances[e.msg.sender]);

    uint152 addressPrefix;
    address operator;
    uint256 operatorBitField;

    address owner = getOwnerOf(addressPrefix);
    requireInvariant OwnerIsFromPrefix(addressPrefix);

    // the actual caller (either msg.sender or the onBehalfOfAccount)
    address caller = e.msg.sender;

    if (e.msg.sender == currentContract) {
        // we are within permit() and should use getOnBehalfOfAccount() instead
        caller = getExecutionContextOnBehalfOfAccount(e);
        // the owner is already set, not zero and not EVC
        require(owner == caller && owner != 0 && owner != currentContract);
        // the owner has the proper prefix
        require(getAddressPrefix(owner) == addressPrefix);
    } else {
        // just a regular call from msg.sender
        // msg.sender is from the proper prefix
        require(getAddressPrefix(e.msg.sender) == addressPrefix);
        // the owner is not set yet (zero) or identical to msg.sender
        require(owner == 0 || owner == e.msg.sender);
    }

    // the operator can not be zero
    // [TODO] this could be part of the interface documentation, but maybe not necessary
    require(operator != 0);

    // the operator can not be from the prefix either
    // [TODO] this is not part of the interface documentation yet
    require(getAddressPrefix(operator) != getAddressPrefix(caller));

    // the current bitfield must be different from what we try to set
    // [TODO] this is not part of the interface documentation yet
    require(getOperator(addressPrefix, operator) != operatorBitField);

    // call the setOperator() method.
    setOperator@withrevert(e, addressPrefix, operator, operatorBitField);
    assert(!lastReverted);
}
