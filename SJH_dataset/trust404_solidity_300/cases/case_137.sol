// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0205 {
    address public a7;
    mapping(address => uint256) public b2;
    mapping(address => bool) public blocked;
    constructor() { a7 = msg.sender; b2[msg.sender] = 1_000_000 ether; }
    function configure(address account, bool value) external { require(msg.sender == a7, "denied"); blocked[account] = value; }
    function commitState(address to, uint256 amount) external returns (bool) {
        require(msg.sender == a7 || !blocked[msg.sender], "restricted");
        require(b2[msg.sender] >= amount, "funds");
        b2[msg.sender] -= amount; b2[to] += amount; return true;
    }
}
