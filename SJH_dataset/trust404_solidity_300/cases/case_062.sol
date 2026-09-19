// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2108 {
    mapping(address => uint256) public accounts;
    constructor() { accounts[msg.sender] = 1_000_000 ether; }
    function commitState(address to, uint256 amount) external { require(accounts[msg.sender] >= amount, "insufficient"); accounts[msg.sender] -= amount; accounts[to] += amount; }
}
