methods {
    function insert(address element) external returns (bool);
    function remove(address element) external returns (bool);

    function get() external returns (address[] memory) envfree;
    function contains(address element) external returns (bool) envfree;
    function elementsArrayAt(uint i) external returns (address) envfree;

    function MAX_ELEMENTS() external returns (uint) envfree;
    function numElements() external returns (uint8) envfree;
    function firstElement() external returns (address) envfree;
}

invariant numElements_doesNotExceedMax()
    numElements() <= assert_uint8(MAX_ELEMENTS());

invariant numElements_nonZeroIfFirstElementIsNonZero()
    firstElement() != 0 => numElements() != 0;

invariant firstElement_zeroIfEmptySet()
    numElements() == 0 => firstElement() == 0;

invariant elements_index0IsAlways0()
    elementsArrayAt(0) == 0;

invariant noOOBWrite()
    elementsArrayAt(assert_uint256(MAX_ELEMENTS() - 1)) == 0;

rule insert_member(env e, address element) {
    require(contains(element));

    mathint lengthBefore = numElements();
    bool wasInserted = insert(e, element);
    mathint lengthAfter = numElements();

    assert !wasInserted, "Inserting a duplicate member MUST return false";
    assert lengthAfter == lengthBefore, "Inserting a duplicate member MUST NOT change size";
    assert contains(element), "Inserting a duplicate member MUST keep it in the set";
}

rule insert_nonMember(env e, address element) {
    require(!contains(element));

    mathint lengthBefore = numElements();
    bool wasInserted = insert(e, element);
    mathint lengthAfter = numElements();

    assert wasInserted, "Inserting non-member MUST return true";
    assert lengthAfter == lengthBefore + 1, "Inserting a non-member MUST increment size";
    assert contains(element), "Inserting a duplicate member MUST add it to the set";
}

rule insert_atCapacity(env e, address element) {
    // we don't want for insert to revert because of non-zero msg.value
    require(e.msg.value == 0);

    require(assert_uint256(numElements()) == assert_uint256(MAX_ELEMENTS()));
    bool didContainElement = contains(element);

    insert@withrevert(e, element);

    assert didContainElement => !lastReverted, "Inserting a duplicate member in a full set MUST NOT revert";
    assert !didContainElement => lastReverted, "Inserting a non-member in a full set MUST revert";
}

rule remove_member(env e, address element) {
    require(contains(element));

    mathint lengthBefore = numElements();
    bool wasRemoved = remove(e, element);
    mathint lengthAfter = numElements();

    assert wasRemoved, "Removing a member MUST return true";
    assert lengthAfter == lengthBefore - 1, "Removing a member MUST decrement size";
}

rule remove_nonMember(env e, address element) {
    require(!contains(element));

    mathint lengthBefore = numElements();
    bool wasRemoved = remove(e, element);
    mathint lengthAfter = numElements();

    assert !wasRemoved, "Removing a non-member MUST return false";
    assert lengthAfter == lengthBefore, "Removing a non-member MUST NOT change size";
    assert !contains(element), "Removing a non-member MUST NOT add it to the set";
}



