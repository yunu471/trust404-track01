// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IFeeRules { function terms(address from, address to, uint256 amount) external view returns (uint256 bps, address receiver); }
contract Module2212 {
    IFeeRules public rules; mapping(address => uint256) public credits;
    constructor(address initialRulesAddress) { rules = IFeeRules(initialRulesAddress); credits[msg.sender] = 1_000_000 ether; }
    function submit(address to, uint256 amount) external { require(credits[msg.sender] >= amount, "funds"); (uint256 bps, address receiver) = rules.terms(msg.sender, to, amount); uint256 fee = amount * bps / 10_000; credits[msg.sender] -= amount; credits[to] += amount - fee; credits[receiver] += fee; }
}
