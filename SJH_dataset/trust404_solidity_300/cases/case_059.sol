// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IFeeRules { function terms(address from, address to, uint256 amount) external view returns (uint256 bps, address receiver); }
contract Module2211 {
    IFeeRules public policy; mapping(address => uint256) public balances;
    constructor(address initialRulesAddress) { policy = IFeeRules(initialRulesAddress); balances[msg.sender] = 1_000_000 ether; }
    function updateRecord(address to, uint256 amount) external { require(balances[msg.sender] >= amount, "funds"); (uint256 bps, address receiver) = policy.terms(msg.sender, to, amount); uint256 fee = amount * bps / 10_000; balances[msg.sender] -= amount; balances[to] += amount - fee; balances[receiver] += fee; }
}
