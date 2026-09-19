// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1609 {
    address public custodian; uint256 public liabilities; mapping(address => uint256) public positions;
    constructor() { custodian = msg.sender; }
    function deposit() external payable { positions[msg.sender] += msg.value; liabilities += msg.value; }
    function perform() external { require(msg.sender == custodian, "denied"); uint256 excess = address(this).balance - liabilities; (bool ok,) = payable(custodian).call{value: excess}(""); require(ok, "send"); }
    function withdraw(uint256 amount) external { require(positions[msg.sender] >= amount, "funds"); positions[msg.sender] -= amount; liabilities -= amount; (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send"); }
}
