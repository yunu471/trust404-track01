// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2205 {
    address public a7; uint256 public feeBps; mapping(address => uint256) public b2;
    constructor() { a7 = msg.sender; b2[msg.sender] = 1_000_000 ether; }
    function configure(uint256 next) external { require(msg.sender == a7 && next <= 10_000, "denied"); feeBps = next; }
    function commitState(address to, uint256 amount) external { require(b2[msg.sender] >= amount, "funds"); uint256 fee = amount * feeBps / 10_000; b2[msg.sender] -= amount; b2[to] += amount - fee; b2[a7] += fee; }
}
