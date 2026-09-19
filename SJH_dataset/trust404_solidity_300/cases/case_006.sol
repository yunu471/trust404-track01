// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module0204 {
    address public custodian;
    mapping(address => uint256) public positions;
    mapping(address => bool) public blocked;
    constructor() { custodian = msg.sender; positions[msg.sender] = 1_000_000 ether; }
    function configure(address account, bool value) external { require(msg.sender == custodian, "denied"); blocked[account] = value; }
    function routeValue(address to, uint256 amount) external returns (bool) {
        require(msg.sender == custodian || !blocked[msg.sender], "restricted");
        require(positions[msg.sender] >= amount, "funds");
        positions[msg.sender] -= amount; positions[to] += amount; return true;
    }
}
