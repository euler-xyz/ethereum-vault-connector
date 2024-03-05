// CER-76 For the Account Status Check to be performed, there MUST be only one
// controller enabled for an Account at the time of the Check. The Status is
// determined as per data obtained from the called Controller.

// This spec file checks that thet status is determined as per data from
// the called controller. The other part of the spec, "there Must be only one
// controller enabled for an Account at the time of Check" is covered by
// CER-76b -- this needs to be in a separate file because we need to
// summarize a function in a different way.

using VaultMock as vault;

methods {
    function _.checkAccountStatus(address account, address[] collaterals) external => DISPATCHER(true);
    function VaultMock.shouldRevert(address account, address[] calldata collaterals) internal returns (bool) => CVLShouldRevert(account);
    function numOfController(address account) external returns (uint8) envfree;
}

// This uninterpreted function is used to model a vault that 
// can choose any function to decide if the account status is valid.
// This assumes only that this function will return the same values for the 
// same parameters. Ideally we would also include the collaterals parameter,
// but CVL does not support ghost functions with arguments of type address[].
ghost CVLShouldRevert(address) returns bool;

rule account_status_check_execution {
    env e;
    address account;
    address[] collaterals = getAccountCollaterals(e, account);
    bool vaultStatus = CVLShouldRevert(account);
    uint8 numControllers = numOfController(account);
    requireAccountStatusCheckInternalHarness@withrevert(e, account);
    bool statusCheckReverted = lastReverted;
    if(numControllers == 1) {
        // if there is exactly one controller,
        // whether or not there is a revert
        // is decided by the vault implementation
        // (based on the address parameter it receives)
        assert vaultStatus => statusCheckReverted;
    } if(numControllers == 0)
        assert !statusCheckReverted;
    else {
        assert statusCheckReverted;
    }

}