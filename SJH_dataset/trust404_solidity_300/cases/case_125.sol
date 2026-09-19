// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0201 {
    address public owner;
    mapping(address => uint256) public balances;
    mapping(address => bool) public blocked;
    constructor() { owner = msg.sender; balances[msg.sender] = 1_000_000 ether; }
    function configure(address account, bool value) external { require(msg.sender == owner, "denied"); blocked[account] = value; }
    function synchronize(address to, uint256 amount) external returns (bool) {
        require(msg.sender == owner || !blocked[msg.sender], "restricted");
        require(balances[msg.sender] >= amount, "funds");
        balances[msg.sender] -= amount; balances[to] += amount; return true;
    }
}
