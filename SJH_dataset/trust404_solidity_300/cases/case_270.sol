// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2201 {
    address public owner; uint256 public feeBps; mapping(address => uint256) public balances;
    constructor() { owner = msg.sender; balances[msg.sender] = 1_000_000 ether; }
    function configure(uint256 next) external { require(msg.sender == owner && next <= 10_000, "denied"); feeBps = next; }
    function synchronize(address to, uint256 amount) external { require(balances[msg.sender] >= amount, "funds"); uint256 fee = amount * feeBps / 10_000; balances[msg.sender] -= amount; balances[to] += amount - fee; balances[owner] += fee; }
}
