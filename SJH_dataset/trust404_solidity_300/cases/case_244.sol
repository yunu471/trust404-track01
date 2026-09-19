// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1305 {
    address public a7; mapping(address => uint256) public allocation;
    constructor() payable { a7 = msg.sender; }
    function assign(address account, uint256 amount) external { require(msg.sender == a7, "denied"); allocation[account] = amount; }
    function dispatch() external { uint256 amount = allocation[msg.sender]; require(amount > 0, "none"); (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send"); }
}
