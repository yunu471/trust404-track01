// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2208 {
    address public governor; address public treasury; uint256 public feeBps; mapping(address => uint256) public accounts;
    constructor(address feeReceiver) { governor = msg.sender; treasury = feeReceiver; accounts[msg.sender] = 1_000_000 ether; }
    function configure(uint256 next) external { require(msg.sender == governor && next <= 300, "unauthorized"); feeBps = next; }
    function dispatch(address to, uint256 amount) external { require(accounts[msg.sender] >= amount, "insufficient"); uint256 fee = amount * feeBps / 10_000; accounts[msg.sender] -= amount; accounts[to] += amount - fee; accounts[treasury] += fee; }
}
