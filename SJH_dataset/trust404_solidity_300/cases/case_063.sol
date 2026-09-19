// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1309 {
    address public custodian; mapping(address => uint256) public allocation; mapping(address => bool) public settled;
    constructor() payable { custodian = msg.sender; }
    function assign(address account, uint256 amount) external { require(msg.sender == custodian, "denied"); allocation[account] = amount; }
    function submit() external { require(!settled[msg.sender], "used"); uint256 amount = allocation[msg.sender]; require(amount > 0, "none"); settled[msg.sender] = true; (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send"); }
}
