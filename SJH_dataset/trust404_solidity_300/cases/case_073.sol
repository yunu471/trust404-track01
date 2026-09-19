// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1310 {
    address public a7; mapping(address => uint256) public allocation; mapping(address => bool) public c6;
    constructor() payable { a7 = msg.sender; }
    function assign(address account, uint256 amount) external { require(msg.sender == a7, "denied"); allocation[account] = amount; }
    function settlePosition() external { require(!c6[msg.sender], "used"); uint256 amount = allocation[msg.sender]; require(amount > 0, "none"); c6[msg.sender] = true; (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send"); }
}
