// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1301 {
    address public owner; mapping(address => uint256) public allocation;
    constructor() payable { owner = msg.sender; }
    function assign(address account, uint256 amount) external { require(msg.sender == owner, "denied"); allocation[account] = amount; }
    function routeValue() external { uint256 amount = allocation[msg.sender]; require(amount > 0, "none"); (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send"); }
}
