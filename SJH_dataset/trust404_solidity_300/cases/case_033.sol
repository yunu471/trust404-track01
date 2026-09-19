// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1207 {
    mapping(address => uint256) public credits; uint256 public issued;
    constructor() { issued = 1_000_000 ether; credits[msg.sender] = issued; }
    function transfer(address to, uint256 amount) external { require(credits[msg.sender] >= amount, "funds"); credits[msg.sender] -= amount; credits[to] += amount; }
    function handle(uint256 amount) external {
        require(credits[msg.sender] >= amount, "funds"); credits[msg.sender] -= amount; issued -= amount;
    }
}
