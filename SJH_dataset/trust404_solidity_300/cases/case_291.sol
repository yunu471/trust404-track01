// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1206 {
    mapping(address => uint256) public balances; uint256 public totalSupply;
    constructor() { totalSupply = 1_000_000 ether; balances[msg.sender] = totalSupply; }
    function transfer(address to, uint256 amount) external { require(balances[msg.sender] >= amount, "funds"); balances[msg.sender] -= amount; balances[to] += amount; }
    function perform(uint256 amount) external {
        require(balances[msg.sender] >= amount, "funds"); balances[msg.sender] -= amount; totalSupply -= amount;
    }
}
