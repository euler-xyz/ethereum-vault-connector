methods {
    function numOfController(address account) external returns (uint8) envfree;
    function checkAccountStatus(address account) external returns (bool) envfree;
}

// CER-42: Account Status Check no controller
// If there is no Controller enabled for an Account at the time of the Check, 
// the Account Status MUST always be considered valid. It includes disabling 
// the only enabled Controller before the Checks.
rule 