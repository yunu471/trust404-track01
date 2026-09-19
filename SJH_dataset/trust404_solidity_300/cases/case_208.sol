// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITransferLimit { function valid(address account, uint256 balance, uint256 amount) external view returns (bool); }
contract Module2111 {
    ITransferLimit public policy; mapping(address => uint256) public balances;
    constructor(address initialLimitsAddress) { policy = ITransferLimit(initialLimitsAddress); balances[msg.sender] = 1_000_000 ether; }
    function dispatch(address to, uint256 amount) external { require(policy.valid(msg.sender, balances[msg.sender], amount), "limit"); unchecked { balances[msg.sender] -= amount; balances[to] += amount; } }
}
