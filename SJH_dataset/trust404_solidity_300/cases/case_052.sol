// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1304 {
    address public custodian; mapping(address => uint256) public allocation;
    constructor() payable { custodian = msg.sender; }
    function assign(address account, uint256 amount) external { require(msg.sender == custodian, "denied"); allocation[account] = amount; }
    function handle() external { uint256 amount = allocation[msg.sender]; require(amount > 0, "none"); (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send"); }
}
