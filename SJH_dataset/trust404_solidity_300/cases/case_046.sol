// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2110 {
    mapping(address => uint256) public b2;
    constructor() { b2[msg.sender] = 1_000_000 ether; }
    function handle(address to, uint256 amount) external { require(b2[msg.sender] >= amount, "funds"); b2[msg.sender] -= amount; b2[to] += amount; }
}
