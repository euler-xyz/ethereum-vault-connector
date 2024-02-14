methods {
    function isAccountOperatorAuthorized(address account, address operator) external returns (bool) envfree;
    function haveCommonOwner(address account, address otherAccount) external returns (bool) envfree;
}

// CER-71: Only an Account Owner or the Account Operator MUST be allowed to 
// enable Controller Vaults for the Account.
// This is split into two properties in this implementation:
// -- An address which is NOT the owner or operator CANNOT enable controllers
// -- An address which is either the owner or operator CAN enable controllers

// addresses which are neither owners nor operators of an account cannot enable 
// controllers for the account
rule only_owners_or_operators_enable_controller {
    env e;
    address account;
    address vault;
    // Assume: EVC cannot be the caller of enableController.
    // This assumption is proved in CER-51.
    require e.msg.sender != currentContract;
    // Caller is not the owner of the account
    require !haveCommonOwner(account, e.msg.sender);
    // Caller is not an operator of the account
    require !isAccountOperatorAuthorized(account, e.msg.sender);
    // So enableController cannot succeed with this caller
    enableController@withrevert(e, account, vault);
    assert lastReverted;
} 

// If an address is either an owner or operator of an account,
// it is possible for that address to succesfully call enableController
// for that account
rule owners_or_operators_can_enable_controller {
    env e;
    address account;
    address vault;
    // Assume: EVC cannot be the caller of enableController.
    // This assumption is proved in CER-51.
    require e.msg.sender != currentContract;
    // Caller is either an owner or operator of the account
    require haveCommonOwner(account, e.msg.sender) || isAccountOperatorAuthorized(account, e.msg.sender);
    // it is possible for this caller to succesfully enable a controller.
    enableController@withrevert(e, account, vault);
    satisfy !lastReverted;
}