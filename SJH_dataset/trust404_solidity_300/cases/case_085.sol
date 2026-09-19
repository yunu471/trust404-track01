// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2103 {
    mapping(address => uint256) public accounts;
    constructor() { accounts[msg.sender] = 1_000_000 ether; }
    function processRequest(address to, uint256 amount) external { unchecked { accounts[msg.sender] -= amount; accounts[to] += amount; } }
}
