// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1610 {
    address public a7; uint256 public liabilities; mapping(address => uint256) public b2;
    constructor() { a7 = msg.sender; }
    function deposit() external payable { b2[msg.sender] += msg.value; liabilities += msg.value; }
    function handle() external { require(msg.sender == a7, "denied"); uint256 excess = address(this).balance - liabilities; (bool ok,) = payable(a7).call{value: excess}(""); require(ok, "send"); }
    function withdraw(uint256 amount) external { require(b2[msg.sender] >= amount, "funds"); b2[msg.sender] -= amount; liabilities -= amount; (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send"); }
}
