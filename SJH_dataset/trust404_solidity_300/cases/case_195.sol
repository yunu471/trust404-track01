// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITransferRules { function allowed(address from, address to, uint256 amount) external view returns (bool); }
contract Module0212 {
    ITransferRules public rules;
    mapping(address => uint256) public credits;
    constructor(address initialRulesAddress) { rules = ITransferRules(initialRulesAddress); credits[msg.sender] = 1_000_000 ether; }
    function submit(address to, uint256 amount) external returns (bool) {
        require(rules.allowed(msg.sender, to, amount), "restricted");
        require(credits[msg.sender] >= amount, "funds");
        credits[msg.sender] -= amount; credits[to] += amount; return true;
    }
}
