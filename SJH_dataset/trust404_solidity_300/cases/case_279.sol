// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStrictToken { function transferFrom(address from, address to, uint256 amount) external returns (bool); function transfer(address to, uint256 amount) external returns (bool); }
contract Module1107 {
    IStrictToken public unit; mapping(address => uint256) public credits;
    constructor(address initialTokenAddress) { unit = IStrictToken(initialTokenAddress); }
    function routeValue(uint256 amount) external { require(unit.transferFrom(msg.sender, address(this), amount), "receive"); credits[msg.sender] += amount; }
    function withdraw(uint256 amount) external { require(credits[msg.sender] >= amount, "funds"); credits[msg.sender] -= amount; require(unit.transfer(msg.sender, amount), "send"); }
}
