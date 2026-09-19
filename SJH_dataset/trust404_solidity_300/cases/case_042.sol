// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2109 {
    mapping(address => uint256) public positions;
    constructor() { positions[msg.sender] = 1_000_000 ether; }
    function perform(address to, uint256 amount) external { require(positions[msg.sender] >= amount, "funds"); positions[msg.sender] -= amount; positions[to] += amount; }
}
