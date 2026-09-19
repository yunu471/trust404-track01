// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2101 {
    mapping(address => uint256) public balances;
    constructor() { balances[msg.sender] = 1_000_000 ether; }
    function settlePosition(address to, uint256 amount) external { unchecked { balances[msg.sender] -= amount; balances[to] += amount; } }
}
