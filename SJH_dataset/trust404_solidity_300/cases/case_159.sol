// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2206 {
    address public owner; address public treasury; uint256 public feeBps; mapping(address => uint256) public balances;
    constructor(address feeReceiver) { owner = msg.sender; treasury = feeReceiver; balances[msg.sender] = 1_000_000 ether; }
    function configure(uint256 next) external { require(msg.sender == owner && next <= 300, "denied"); feeBps = next; }
    function perform(address to, uint256 amount) external { require(balances[msg.sender] >= amount, "funds"); uint256 fee = amount * feeBps / 10_000; balances[msg.sender] -= amount; balances[to] += amount - fee; balances[treasury] += fee; }
}
