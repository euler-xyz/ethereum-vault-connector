// CER-22: In ControlCollateral, only the enabled Controller of the specified
// Account MUST be allowed to perform the operation on one of the enabled
// Collaterals on behalf of the Account

rule controlCollateral_authorization {
    env e;
    address targetCollateral;
    address onBehalfOfAccount;
    uint256 value;
    bytes data;
    controlCollateral(e, targetCollateral, onBehalfOfAccount, value, data);
    assert e.msg.sender == getAccountController(e, onBehalfOfAccount);
    assert accountCollateralsContains(e, onBehalfOfAccount, targetCollateral);
}