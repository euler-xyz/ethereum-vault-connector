//-----------------------------------------------------------------------------
// Benchmarking specs
//-----------------------------------------------------------------------------
// These specs are here only to benchmark the performance of the contracts. They
// are not necessarily meant to cover any security goals.

rule sanity(method f) {
    env e; calldataarg args;

    f(e,args);
    satisfy true;
}

// Check for privileged operations
rule privilegedOperation(method f, address privileged)
description "$f can be called by more than one user without reverting"
{
	env e1;
	calldataarg arg;
	require (e1.msg.sender == privileged);
	f@withrevert(e1, arg); // privileged succeeds executing candidate privileged operation.
	bool firstSucceeded = !lastReverted;

	env e2;
	calldataarg arg2;
	require (e2.msg.sender != privileged);
	f@withrevert(e2, arg2); // unprivileged
	bool secondSucceeded = !lastReverted;

	assert !(firstSucceeded && secondSucceeded), "$f can be called by both ${e1.msg.sender} and ${e2.msg.sender}, so it is not privileged";
}