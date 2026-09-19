// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1302 {
    address public steward; mapping(address => uint256) public allocation;
    constructor() payable { steward = msg.sender; }
    function assign(address account, uint256 amount) external { require(msg.sender == steward, "denied"); allocation[account] = amount; }
    function commitState() external { uint256 amount = allocation[msg.sender]; require(amount > 0, "none"); (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send"); }
}
