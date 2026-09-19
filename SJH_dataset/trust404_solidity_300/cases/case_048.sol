// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ILooseToken { function transferFrom(address from, address to, uint256 amount) external returns (bool); function transfer(address to, uint256 amount) external returns (bool); }
contract Module1102 {
    ILooseToken public unit; mapping(address => uint256) public credits;
    constructor(address initialTokenAddress) { unit = ILooseToken(initialTokenAddress); }
    function applyUpdate(uint256 amount) external { unit.transferFrom(msg.sender, address(this), amount); credits[msg.sender] += amount; }
    function withdraw(uint256 amount) external { require(credits[msg.sender] >= amount, "funds"); credits[msg.sender] -= amount; require(unit.transfer(msg.sender, amount), "send"); }
}
