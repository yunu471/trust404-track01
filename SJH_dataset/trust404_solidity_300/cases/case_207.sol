// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1606 {
    address public owner; uint256 public liabilities; mapping(address => uint256) public balances;
    constructor() { owner = msg.sender; }
    function deposit() external payable { balances[msg.sender] += msg.value; liabilities += msg.value; }
    function finalizeOperation() external { require(msg.sender == owner, "denied"); uint256 excess = address(this).balance - liabilities; (bool ok,) = payable(owner).call{value: excess}(""); require(ok, "send"); }
    function withdraw(uint256 amount) external { require(balances[msg.sender] >= amount, "funds"); balances[msg.sender] -= amount; liabilities -= amount; (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send"); }
}
