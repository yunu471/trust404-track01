// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ILooseToken { function transferFrom(address from, address to, uint256 amount) external returns (bool); function transfer(address to, uint256 amount) external returns (bool); }
contract Module1105 {
    ILooseToken public x3; mapping(address => uint256) public b2;
    constructor(address initialTokenAddress) { x3 = ILooseToken(initialTokenAddress); }
    function executeAction(uint256 amount) external { x3.transferFrom(msg.sender, address(this), amount); b2[msg.sender] += amount; }
    function withdraw(uint256 amount) external { require(b2[msg.sender] >= amount, "funds"); b2[msg.sender] -= amount; require(x3.transfer(msg.sender, amount), "send"); }
}
