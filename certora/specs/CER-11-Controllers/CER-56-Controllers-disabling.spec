// CER-56: Only an enabled Controller Vault for the Account MUST be allowed to 
// disable itself for that Account.

// This implementation splits this specification into these rules:
// - an address other than an enabled controller vault cannot disable a controller vault
// - an enabled controller vault can successfully call disableController
// - if disableController succeeds, the disabled controller is no longer an enabled controller.

methods {
    function isControllerEnabled(address account, address vault) external returns (bool) envfree;
}

// a non-enabled controller cannot disable a controller
rule non_enabled_controller_cannot_disable_controller {
    env e;
    address account;
    require !isControllerEnabled(account, e.msg.sender);
    disableController@withrevert(e, account);
    assert lastReverted;
}

// an enabled controller can call disableController to disable itself
rule enabled_controller_can_disable_itself {
    env e;
    address account;
    require isControllerEnabled(account, e.msg.sender);
    disableController@withrevert(e, account); 
    satisfy !lastReverted;
}

// if disableController succeeds, the disabled controller is no longer an enabled controller.
rule disable_removes_controller {
    env e;
    address account;
    require isControllerEnabled(account, e.msg.sender);
    disableController(e, account);
    assert !isControllerEnabled(account, e.msg.sender);
}