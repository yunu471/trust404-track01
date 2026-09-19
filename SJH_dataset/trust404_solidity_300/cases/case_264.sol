// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Module2207 {
    address public steward; address public treasury; uint256 public feeBps; mapping(address => uint256) public credits;
    constructor(address feeReceiver) { steward = msg.sender; treasury = feeReceiver; credits[msg.sender] = 1_000_000 ether; }
    function configure(uint256 next) external { require(msg.sender == steward && next <= 300, "denied"); feeBps = next; }
    function handle(address to, uint256 amount) external { require(credits[msg.sender] >= amount, "funds"); uint256 fee = amount * feeBps / 10_000; credits[msg.sender] -= amount; credits[to] += amount - fee; credits[treasury] += fee; }
}
