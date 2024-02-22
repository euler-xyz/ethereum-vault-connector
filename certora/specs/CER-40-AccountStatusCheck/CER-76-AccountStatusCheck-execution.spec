// CER-76 For the Account Status Check to be performed, there MUST be only one
// controller enabled for an Account at the time of the Check. The Status is
// determined as per data obtained from the called Controller.

using VaultMock as vault;

methods {
    function _.checkAccountStatus(address account, address[] collaterals) external => DISPATCHER(true);
    function VaultMock.shouldRevert(address account, address[] calldata collaterals) internal returns (bool) => CVLShouldRevert(account);
    function numOfController(address account) external returns (uint8) envfree;
}

// This uninterpreted function is used to model a vault that 
// can choose any function to decide if the account status is valid.
// This assumes only that this function will return the same values for the 
// same parameters.
ghost CVLShouldRevert(address) returns bool;

rule account_status_check_execution {
    env e;
    address account;
    address[] collaterals = getAccountCollaterals(e, account);
    bool vaultStatus = CVLShouldRevert(account);
    requireAccountStatusCheckInternalHarness@withrevert(e, account);
    assert lastReverted == vaultStatus;
    assert !lastReverted => numOfController(account) <= 1;

}