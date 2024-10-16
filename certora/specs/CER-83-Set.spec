/* Verification of `Set` library 
Full run: https://prover.certora.com/output/40726/c4fecbacb03045a28f210f7c0ca7c67a/?anonymousKey=1f4e421af7ce97274005b30761e9fb75a78d5aa0
Mutation run:  https://mutation-testing.certora.com/?id=8239ff0c-739c-4451-be5e-8b69336ccf7b&anonymousKey=c8d17ebd-bc1f-48e7-b201-a9e2bcf22d2b

*/
methods {
    function insert(address) external returns (bool) envfree;
    function remove(address) external returns (bool) envfree;
    function reorder(uint8, uint8) external envfree;
    function contains(address) external returns (bool) envfree;
}


definition get(uint8 index)  returns address  =
        (index==0 ? currentContract.setStorage.firstElement : currentContract.setStorage.elements[index].value);

definition length() returns uint8 =  currentContract.setStorage.numElements;


/// @title Elements in set are unique
invariant uniqueElements() 
    forall uint8 i. forall uint8 j. 
        (i < length() && j < length() && i != j => get(i) != get(j)) 
    {
        preserved reorder(uint8 m, uint8 n) {
            //need to help the grounding a bit
            require uniqueElements_assumption(m,0);
            require uniqueElements_assumption(m,n);
            require uniqueElements_assumption(n,0);
        }
    }

//  Invariant uniqueElements is proven for all values, therefore it is safe to assume for two individual entries 
definition uniqueElements_assumption(uint8 i, uint8 j) returns bool = 
    (i < length() && j < length() && i != j => get(i) != get(j)) ;



/// @title The length of the set can change at most by 1
rule setLengthChangedByOne(method f) {
    uint8 lengthBefore = length();

    env e;
    calldataarg args;
    f(e, args);

    uint8 lengthAfter = length();
    assert lengthAfter <= lengthBefore + 1;
}


/// @title Length is increased only by insert and decreased only by remove
/// Meaning:
/// - If the length increased then `insert` was called
/// - If the length decreased then `remove` was called
rule setLengthIncreaseDecrease(method f) {
    uint8 lengthBefore = length();

    env e;
    calldataarg args;
    f(e, args);

    uint8 lengthAfter = length();
    assert lengthAfter > lengthBefore => f.selector == sig:insert(address).selector;
    assert lengthAfter < lengthBefore => f.selector == sig:remove(address).selector;
}



// CER-86 Set insert: contains must return true if an element is present in 
// the set. (This is specified in combination with validSet/containsIntegrity)
rule contained_if_inserted(address a) {
    env e;
    insert(a);
    assert(contains(a));
}

// CER-91: set library MUST remove an element from the set if it's present
rule not_contained_if_removed(address a) {
    env e;
    requireInvariant uniqueElements();
    require uniqueElements_assumption(0,1);
    require uniqueElements_assumption(0,2);
    require uniqueElements_assumption(1,2);
    remove(a);
    assert(!contains(a));
}

// CER-90: remove must return true if an element was successfully removed from 
// the set.remove must return false if an element was not removed from the set.
// (In other words it returns true if and only if an element is removed).
rule removed_iff_not_contained(address a) {
    env e;
    requireInvariant uniqueElements();
    bool containsBefore = contains(a);
    bool succ = remove(a);
    assert(succ <=> containsBefore);
}

/** @title remove decreases the number of elements by one */
rule removed_then_length_decrease(address a) {
    env e;
    requireInvariant uniqueElements();
    mathint lengthBefore = length();
    bool succ = remove(a);
    assert(succ => length() == lengthBefore - 1);
}

use builtin rule sanity; 