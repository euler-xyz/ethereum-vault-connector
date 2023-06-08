// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

interface IEulerMarket {
    function touch() external;
    function deposit(address primary, uint subAccountId, uint amount, address msgSender) external returns (bool hasOutstandingDeposit);
    function withdraw(address primary, uint subAccountId, uint amount) external returns (bool hasOutstandingDeposit);
    function borrow(address primary, uint subAccountId, uint amount) external returns (bool hasOutstandingDebt);
    function repay(address primary, uint subAccountId, uint amount) external returns (bool hasOutstandingDebt);
    function depositAndBorrow(address primary, uint subAccountId, uint amount) external returns (bool hasOutstandingDebt);
    function repayAndWithdraw(address primary, uint subAccountId, uint amount) external returns (bool hasOutstandingDebt);
    function flashLoan(address initiator, uint amount, bytes calldata data) external;
    function hook(uint8 hookNumber, bytes memory data) external;
}
