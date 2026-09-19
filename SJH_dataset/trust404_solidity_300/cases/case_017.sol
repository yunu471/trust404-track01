// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1608 {
    address public governor; uint256 public liabilities; mapping(address => uint256) public accounts;
    constructor() { governor = msg.sender; }
    function deposit() external payable { accounts[msg.sender] += msg.value; liabilities += msg.value; }
    function commitState() external { require(msg.sender == governor, "unauthorized"); uint256 excess = address(this).balance - liabilities; (bool ok,) = payable(governor).call{value: excess}(""); require(ok, "send"); }
    function withdraw(uint256 amount) external { require(accounts[msg.sender] >= amount, "insufficient"); accounts[msg.sender] -= amount; liabilities -= amount; (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send"); }
}
