// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1308 {
    address public governor; mapping(address => uint256) public allocation; mapping(address => bool) public redeemed;
    constructor() payable { governor = msg.sender; }
    function assign(address account, uint256 amount) external { require(msg.sender == governor, "unauthorized"); allocation[account] = amount; }
    function updateRecord() external { require(!redeemed[msg.sender], "used"); uint256 amount = allocation[msg.sender]; require(amount > 0, "none"); redeemed[msg.sender] = true; (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send"); }
}
