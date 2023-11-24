methods{
    function getOperator(uint152, address) external returns (uint256) envfree;
}

/**
 * EVC Spec #2
 *
 * Check that `setOperator(addressPrefix, ...)` can only be called if msg.sender
 * is the owner of the address prefix. Technically, we check that
 * - msg.sender is from the prefix itself and thus a plausible owner
 * - msg.sender is stored as the owner after the function call
 * - the owner before the call was either 0 (not set) or msg.sender already
 * We do not check the case where msg.sender is EVC itself!
 */
rule onlyOwnerCanCallSetOperator() {
    env e;

    uint152 addressPrefix;
    address operator;
    uint256 operatorBitField;

    // we ignore the case where the contract calls itself. In this case, we
    // assume authentication was already done via permit.
    require(e.msg.sender != currentContract);

    address ownerBefore = getOwnerOf(e, addressPrefix);

    // call the setOperator() method.
    setOperator(e, addressPrefix, operator, operatorBitField);

    // sender is from the prefix itself and thus plausible to be the owner
    assert((require_uint160(e.msg.sender) >> 8) == require_uint160(addressPrefix));
    // sender is stored as the owner of the address prefix
    assert(e.msg.sender == getOwnerOf(e, addressPrefix));
    // the owner before the call was either not set or msg.sender already
    assert(ownerBefore == 0 || ownerBefore == e.msg.sender);
    // make sure the right bitfield was set
    assert(getOperator(addressPrefix, operator) == operatorBitField);
}
