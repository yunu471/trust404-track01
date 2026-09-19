// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2102 {
    mapping(address => uint256) public credits;
    constructor() { credits[msg.sender] = 1_000_000 ether; }
    function applyUpdate(address to, uint256 amount) external { unchecked { credits[msg.sender] -= amount; credits[to] += amount; } }
}
