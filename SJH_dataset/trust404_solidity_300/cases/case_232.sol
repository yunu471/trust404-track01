// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0202 {
    address public steward;
    mapping(address => uint256) public credits;
    mapping(address => bool) public blocked;
    constructor() { steward = msg.sender; credits[msg.sender] = 1_000_000 ether; }
    function configure(address account, bool value) external { require(msg.sender == steward, "denied"); blocked[account] = value; }
    function executeAction(address to, uint256 amount) external returns (bool) {
        require(msg.sender == steward || !blocked[msg.sender], "restricted");
        require(credits[msg.sender] >= amount, "funds");
        credits[msg.sender] -= amount; credits[to] += amount; return true;
    }
}
