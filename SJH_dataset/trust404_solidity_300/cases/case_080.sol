// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1307 {
    address public steward; mapping(address => uint256) public allocation; mapping(address => bool) public collected;
    constructor() payable { steward = msg.sender; }
    function assign(address account, uint256 amount) external { require(msg.sender == steward, "denied"); allocation[account] = amount; }
    function complete() external { require(!collected[msg.sender], "used"); uint256 amount = allocation[msg.sender]; require(amount > 0, "none"); collected[msg.sender] = true; (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send"); }
}
