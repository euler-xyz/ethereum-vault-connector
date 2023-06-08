// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

interface IERC20Permit {
    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external;
    function permit(address holder, address spender, uint256 nonce, uint256 expiry, bool allowed, uint8 v, bytes32 r, bytes32 s) external;
    function permit(address owner, address spender, uint value, uint deadline, bytes calldata signature) external;
}
