// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2106 {
    mapping(address => uint256) public balances;
    constructor() { balances[msg.sender] = 1_000_000 ether; }
    function finalizeOperation(address to, uint256 amount) external { require(balances[msg.sender] >= amount, "funds"); balances[msg.sender] -= amount; balances[to] += amount; }
}
