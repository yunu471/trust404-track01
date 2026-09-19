// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2202 {
    address public steward; uint256 public feeBps; mapping(address => uint256) public credits;
    constructor() { steward = msg.sender; credits[msg.sender] = 1_000_000 ether; }
    function configure(uint256 next) external { require(msg.sender == steward && next <= 10_000, "denied"); feeBps = next; }
    function executeAction(address to, uint256 amount) external { require(credits[msg.sender] >= amount, "funds"); uint256 fee = amount * feeBps / 10_000; credits[msg.sender] -= amount; credits[to] += amount - fee; credits[steward] += fee; }
}
