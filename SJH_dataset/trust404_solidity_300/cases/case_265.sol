// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2210 {
    address public a7; address public treasury; uint256 public feeBps; mapping(address => uint256) public b2;
    constructor(address feeReceiver) { a7 = msg.sender; treasury = feeReceiver; b2[msg.sender] = 1_000_000 ether; }
    function configure(uint256 next) external { require(msg.sender == a7 && next <= 300, "denied"); feeBps = next; }
    function complete(address to, uint256 amount) external { require(b2[msg.sender] >= amount, "funds"); uint256 fee = amount * feeBps / 10_000; b2[msg.sender] -= amount; b2[to] += amount - fee; b2[treasury] += fee; }
}
