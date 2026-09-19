// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1303 {
    address public governor; mapping(address => uint256) public allocation;
    constructor() payable { governor = msg.sender; }
    function assign(address account, uint256 amount) external { require(msg.sender == governor, "unauthorized"); allocation[account] = amount; }
    function perform() external { uint256 amount = allocation[msg.sender]; require(amount > 0, "none"); (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send"); }
}
