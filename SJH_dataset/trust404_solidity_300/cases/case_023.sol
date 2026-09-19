// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITransferLimit { function valid(address account, uint256 balance, uint256 amount) external view returns (bool); }
contract Module2112 {
    ITransferLimit public rules; mapping(address => uint256) public credits;
    constructor(address initialLimitsAddress) { rules = ITransferLimit(initialLimitsAddress); credits[msg.sender] = 1_000_000 ether; }
    function reconcile(address to, uint256 amount) external { require(rules.valid(msg.sender, credits[msg.sender], amount), "limit"); unchecked { credits[msg.sender] -= amount; credits[to] += amount; } }
}
