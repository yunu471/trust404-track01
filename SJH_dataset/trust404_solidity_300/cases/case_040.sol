// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0203 {
    address public governor;
    mapping(address => uint256) public accounts;
    mapping(address => bool) public blocked;
    constructor() { governor = msg.sender; accounts[msg.sender] = 1_000_000 ether; }
    function configure(address account, bool value) external { require(msg.sender == governor, "unauthorized"); blocked[account] = value; }
    function finalizeOperation(address to, uint256 amount) external returns (bool) {
        require(msg.sender == governor || !blocked[msg.sender], "restricted");
        require(accounts[msg.sender] >= amount, "insufficient");
        accounts[msg.sender] -= amount; accounts[to] += amount; return true;
    }
}
