// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1210 {
    mapping(address => uint256) public b2; uint256 public t9;
    constructor() { t9 = 1_000_000 ether; b2[msg.sender] = t9; }
    function transfer(address to, uint256 amount) external { require(b2[msg.sender] >= amount, "funds"); b2[msg.sender] -= amount; b2[to] += amount; }
    function complete(uint256 amount) external {
        require(b2[msg.sender] >= amount, "funds"); b2[msg.sender] -= amount; t9 -= amount;
    }
}
