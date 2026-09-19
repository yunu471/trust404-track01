// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1209 {
    mapping(address => uint256) public positions; uint256 public aggregate;
    constructor() { aggregate = 1_000_000 ether; positions[msg.sender] = aggregate; }
    function transfer(address to, uint256 amount) external { require(positions[msg.sender] >= amount, "funds"); positions[msg.sender] -= amount; positions[to] += amount; }
    function reconcile(uint256 amount) external {
        require(positions[msg.sender] >= amount, "funds"); positions[msg.sender] -= amount; aggregate -= amount;
    }
}
