// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2204 {
    address public custodian; uint256 public feeBps; mapping(address => uint256) public positions;
    constructor() { custodian = msg.sender; positions[msg.sender] = 1_000_000 ether; }
    function configure(uint256 next) external { require(msg.sender == custodian && next <= 10_000, "denied"); feeBps = next; }
    function routeValue(address to, uint256 amount) external { require(positions[msg.sender] >= amount, "funds"); uint256 fee = amount * feeBps / 10_000; positions[msg.sender] -= amount; positions[to] += amount - fee; positions[custodian] += fee; }
}
