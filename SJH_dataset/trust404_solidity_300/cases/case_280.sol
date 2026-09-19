// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2104 {
    mapping(address => uint256) public positions;
    constructor() { positions[msg.sender] = 1_000_000 ether; }
    function synchronize(address to, uint256 amount) external { unchecked { positions[msg.sender] -= amount; positions[to] += amount; } }
}
