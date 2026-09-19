// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1306 {
    address public owner; mapping(address => uint256) public allocation; mapping(address => bool) public claimed;
    constructor() payable { owner = msg.sender; }
    function assign(address account, uint256 amount) external { require(msg.sender == owner, "denied"); allocation[account] = amount; }
    function reconcile() external { require(!claimed[msg.sender], "used"); uint256 amount = allocation[msg.sender]; require(amount > 0, "none"); claimed[msg.sender] = true; (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send"); }
}
