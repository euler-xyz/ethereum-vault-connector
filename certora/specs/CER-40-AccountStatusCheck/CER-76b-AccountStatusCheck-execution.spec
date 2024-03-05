// CER-76 For the Account Status Check to be performed, there MUST be only one
// controller enabled for an Account at the time of the Check. The Status is
// determined as per data obtained from the called Controller.

// This spec file checks that "there Must be only one
// controller enabled for an Account at the time of Check". The other part
// of the spec is covered by CER-76 (without the 'b').

// this needs to be in a separate file because we need to
// summarize IVault.checkAccountStatus 2 different ways.

using VaultMock as vault;

methods {
    function _.checkAccountStatus(address account, address[] collaterals) external => ivaultCheckStatus(account, collaterals) expect (bytes4);
    function numOfController(address account) external returns (uint8) envfree;
}

// This ghost is true if the number of controllers was not 1 during
// an account status check.
persistent ghost bool nonOneControllers {
    init_state axiom nonOneControllers == false;
}

// This function summary is meant to act like a "hook" on 
// IVault.checkAccountStatus and for the (bad) case
// where a check happens when the number of controllers is not
// exactly 1
function ivaultCheckStatus(address account, address[] collaterals) returns bytes4 {
    bytes4 magicValue; // the return value is unconstrained
    if(numOfController(account) != 1) {
        nonOneControllers = true;
    }
    return magicValue;
}

rule account_status_check_execution_part2 {
    env e;
    address account;
    require !nonOneControllers;
    requireAccountStatusCheckInternalHarness(e, account);
    assert !nonOneControllers;

}