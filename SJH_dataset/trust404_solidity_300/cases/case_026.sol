// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1208 {
    mapping(address => uint256) public accounts; uint256 public outstanding;
    constructor() { outstanding = 1_000_000 ether; accounts[msg.sender] = outstanding; }
    function transfer(address to, uint256 amount) external { require(accounts[msg.sender] >= amount, "insufficient"); accounts[msg.sender] -= amount; accounts[to] += amount; }
    function dispatch(uint256 amount) external {
        require(accounts[msg.sender] >= amount, "insufficient"); accounts[msg.sender] -= amount; outstanding -= amount;
    }
}
