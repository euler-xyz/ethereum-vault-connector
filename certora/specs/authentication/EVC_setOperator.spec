methods {
    function getOperator(uint152, address) external returns (uint256) envfree;
    function getAddressPrefix(address) external returns (uint152) envfree;
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

    address ownerBefore = getOwnerOf(e, addressPrefix);

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
    assert(actualCaller == getOwnerOf(e, addressPrefix));
    // make sure the right bitfield was set
    assert(getOperator(addressPrefix, operator) == operatorBitField);
}

rule nonOwnerCallingSetOperatorReverts() {
    env e;

    uint152 addressPrefix;
    address operator;
    uint256 operatorBitField;

    address owner = getOwnerOf(e, addressPrefix);

    // if msg.sender is the currentContract, it means we are within permit() and
    // we need to use executionContext.getOnBehalfOfAccount() instead.
    address attacker = e.msg.sender;
    if (e.msg.sender == currentContract) {
        attacker = getExecutionContextOnBehalfOfAccount(e);
    }

    if (owner == 0) {
        // prefix has not been claimed, and attacker is not from the prefix
        require(getAddressPrefix(attacker) != addressPrefix);
    } else {
        // prefix has been claimed, but not by the attacker
        require(attacker != owner);
    }

    // call the setOperator() method.
    setOperator@withrevert(e, addressPrefix, operator, operatorBitField);
    assert(lastReverted);
}
