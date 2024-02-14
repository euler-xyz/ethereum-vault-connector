// CER-56: Only an enabled Controller Vault for the Account MUST be allowed to 
// disable itself for that Account.

// This implementation splits this specification into these rules:
// - an enabled controller cannot be disabled by some other address
// - an enabled controller vault can successfully call disableController
// - if disableController succeeds, the disabled controller is no longer an enabled controller.

import "../CER-83-Set.spec";

methods {
    function isControllerEnabled(address account, address vault) external returns (bool) envfree;
}

// an enabled controller cannot be disabled by some other address
rule non_enabled_controller_cannot_disable_controller {
    env e;
    address account;
    address otherController;
    // If otherController is an enabledController...
    require isControllerEnabled(account, otherController);
    // ... and some other address calls disableController...
    require e.msg.sender != otherController;
    disableController(e, account);
    // ... the otherController will not have been disabled
    assert isControllerEnabled(account, otherController);
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
    // These invariants about sets (proved in CER-83-SET)
    // are needed to reason about removal from the 
    // set of controllers
    requireInvariant validSet();
    requireInvariant mirrorIsCorrect(1);
    uint8 _length = assert_uint8(ghostLength);
    requireInvariant mirrorIsCorrect(_length); 

    disableController(e, account);
    assert !isControllerEnabled(account, e.msg.sender);
}