// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1607 {
    address public steward; uint256 public liabilities; mapping(address => uint256) public credits;
    constructor() { steward = msg.sender; }
    function deposit() external payable { credits[msg.sender] += msg.value; liabilities += msg.value; }
    function routeValue() external { require(msg.sender == steward, "denied"); uint256 excess = address(this).balance - liabilities; (bool ok,) = payable(steward).call{value: excess}(""); require(ok, "send"); }
    function withdraw(uint256 amount) external { require(credits[msg.sender] >= amount, "funds"); credits[msg.sender] -= amount; liabilities -= amount; (bool ok,) = msg.sender.call{value: amount}(""); require(ok, "send"); }
}
