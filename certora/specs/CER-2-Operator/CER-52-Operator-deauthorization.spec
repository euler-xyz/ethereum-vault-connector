import "../utils/IsMustRevertFunction.spec";
import "CER-68-Operator-authorization.spec";

methods {
    function getOwnerOf(bytes19) external returns (address) envfree;
    function getOperator(bytes19, address) external returns (uint256) envfree;
    function getAddressPrefix(address) external returns (bytes19) envfree;
    function haveCommonOwner(address account, address otherAccount) external returns (bool) envfree;
}

rule operatorDeauthorization {
    // TODO WIP need to find how deauthorization works
    env e;
    assert true;

}