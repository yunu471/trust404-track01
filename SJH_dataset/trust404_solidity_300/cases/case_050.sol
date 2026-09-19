// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStrictToken { function transferFrom(address from, address to, uint256 amount) external returns (bool); function transfer(address to, uint256 amount) external returns (bool); }
contract Module1108 {
    IStrictToken public token; mapping(address => uint256) public accounts;
    constructor(address initialTokenAddress) { token = IStrictToken(initialTokenAddress); }
    function commitState(uint256 amount) external { require(token.transferFrom(msg.sender, address(this), amount), "receive"); accounts[msg.sender] += amount; }
    function withdraw(uint256 amount) external { require(accounts[msg.sender] >= amount, "insufficient"); accounts[msg.sender] -= amount; require(token.transfer(msg.sender, amount), "send"); }
}
