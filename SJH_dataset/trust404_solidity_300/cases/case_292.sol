// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2107 {
    mapping(address => uint256) public credits;
    constructor() { credits[msg.sender] = 1_000_000 ether; }
    function routeValue(address to, uint256 amount) external { require(credits[msg.sender] >= amount, "funds"); credits[msg.sender] -= amount; credits[to] += amount; }
}
